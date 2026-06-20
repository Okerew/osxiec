#include "globals/globals.h"
#include "osxiec.h"
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/event.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

// Identifier for the EVFILT_USER event used to wake the reaper thread out of
// kevent() during shutdown.
#define REAPER_WAKE_IDENT 1

static void *reaper_thread(void *arg);

// Add pid to the tracking table. Caller must hold reaper.lock.
static void reaper_table_add(pid_t pid, int is_leader) {
  if (pid <= 0) {
    return;
  }
  for (int i = 0; i < reaper.count; i++) {
    if (reaper.pids[i] == pid) {
      return; // already tracked
    }
  }
  if (reaper.count >= REAPER_MAX_PIDS) {
    return; // table full; best effort
  }
  reaper.pids[reaper.count] = pid;
  reaper.is_leader[reaper.count] = is_leader;
  reaper.count++;
}

// Remove pid from the tracking table. Caller must hold reaper.lock.
static void reaper_table_remove(pid_t pid) {
  for (int i = 0; i < reaper.count; i++) {
    if (reaper.pids[i] == pid) {
      reaper.pids[i] = reaper.pids[reaper.count - 1];
      reaper.is_leader[i] = reaper.is_leader[reaper.count - 1];
      reaper.count--;
      return;
    }
  }
}

int reaper_init(void) {
  if (reaper.kq != -1) {
    return 0; // already initialised
  }

  reaper.kq = kqueue();
  if (reaper.kq == -1) {
    perror("reaper: kqueue");
    return -1;
  }

  pthread_mutex_init(&reaper.lock, NULL);
  reaper.count = 0;
  reaper.running = 1;

  // Register a user event so reaper_shutdown() can interrupt the blocking
  // kevent() in the reaper thread.
  struct kevent kev;
  EV_SET(&kev, REAPER_WAKE_IDENT, EVFILT_USER, EV_ADD | EV_CLEAR, 0, 0, NULL);
  if (kevent(reaper.kq, &kev, 1, NULL, 0, NULL) == -1) {
    perror("reaper: register wake event");
  }

  if (pthread_create(&reaper.thread, NULL, reaper_thread, NULL) != 0) {
    perror("reaper: pthread_create");
    close(reaper.kq);
    reaper.kq = -1;
    reaper.running = 0;
    return -1;
  }

  return 0;
}

void reaper_register(pid_t pid, int is_group_leader) {
  if (reaper.kq == -1 || pid <= 0) {
    return; // reaper not active (e.g. API mode outside a container)
  }

  pthread_mutex_lock(&reaper.lock);
  reaper_table_add(pid, is_group_leader);
  pthread_mutex_unlock(&reaper.lock);

  // Watch only for exit. NOTE_TRACK is unsupported on macOS (ENOTSUP), so we
  // cannot follow forks here; subtree cleanup relies on process groups.
  struct kevent kev;
  EV_SET(&kev, pid, EVFILT_PROC, EV_ADD | EV_CLEAR, NOTE_EXIT, 0, NULL);
  if (kevent(reaper.kq, &kev, 1, NULL, 0, NULL) == -1) {
    if (errno == ESRCH) {
      // Already exited before we could watch it; drop it from the table.
      pthread_mutex_lock(&reaper.lock);
      reaper_table_remove(pid);
      pthread_mutex_unlock(&reaper.lock);
    } else {
      // Some other failure (e.g. the sandbox denies the watch). Keep the pid
      // in the table so shutdown still terminates it; just warn once.
      static int warned = 0;
      if (!warned) {
        warned = 1;
        fprintf(stderr,
                "reaper: kevent(EV_ADD) failed (%s); falling back to "
                "process-group cleanup only\n",
                strerror(errno));
      }
    }
  }
}

static void *reaper_thread(void *arg) {
  (void)arg;
  struct kevent events[16];

  while (reaper.running) {
    int n = kevent(reaper.kq, NULL, 0, events, 16, NULL);
    if (n == -1) {
      if (errno == EINTR) {
        continue;
      }
      break;
    }

    for (int i = 0; i < n; i++) {
      struct kevent *ev = &events[i];

      if (ev->filter == EVFILT_USER) {
        continue; // shutdown wake-up; the while-condition re-checks running
      }
      if (ev->filter != EVFILT_PROC) {
        continue;
      }

      if (ev->fflags & NOTE_EXIT) {
        // Process gone. Drop it from the table; its synchronous waiter (if any)
        // reaps the zombie - we must not race that here.
        pthread_mutex_lock(&reaper.lock);
        reaper_table_remove((pid_t)ev->ident);
        pthread_mutex_unlock(&reaper.lock);
      }
    }
  }

  return NULL;
}

// Signal every tracked process. Group leaders take down their whole group via
// killpg(); every pid is also signalled directly to reach descendants that
// escaped the group with setsid(). Returns the number of processes that were
// still alive (i.e. the signal was delivered).
static int reaper_signal_all(int sig) {
  pid_t pids[REAPER_MAX_PIDS];
  int leader[REAPER_MAX_PIDS];
  int count;

  pthread_mutex_lock(&reaper.lock);
  count = reaper.count;
  if (count > 0) {
    memcpy(pids, reaper.pids, (size_t)count * sizeof(pid_t));
    memcpy(leader, reaper.is_leader, (size_t)count * sizeof(int));
  }
  pthread_mutex_unlock(&reaper.lock);

  int alive = 0;
  for (int i = 0; i < count; i++) {
    if (leader[i]) {
      killpg(pids[i], sig);
    }
    if (kill(pids[i], sig) == 0) {
      alive++;
    }
  }
  return alive;
}

void reaper_shutdown(void) {
  if (reaper.kq == -1) {
    return;
  }

  // Stop the loop and wake it out of kevent().
  reaper.running = 0;
  struct kevent kev;
  EV_SET(&kev, REAPER_WAKE_IDENT, EVFILT_USER, 0, NOTE_TRIGGER, 0, NULL);
  kevent(reaper.kq, &kev, 1, NULL, 0, NULL);
  pthread_join(reaper.thread, NULL);

  // Polite termination first, then force anything that ignored SIGTERM.
  if (reaper_signal_all(SIGTERM) > 0) {
    struct timespec grace = {.tv_sec = 0, .tv_nsec = 500L * 1000 * 1000};
    nanosleep(&grace, NULL);
  }
  reaper_signal_all(SIGKILL);

  // Drain leftover zombies. The interactive loop and the synchronous waiters
  // are gone by now, so there is no competing waitpid() to race.
  int status;
  while (waitpid(-1, &status, WNOHANG) > 0) {
  }

  pthread_mutex_lock(&reaper.lock);
  reaper.count = 0;
  pthread_mutex_unlock(&reaper.lock);

  close(reaper.kq);
  reaper.kq = -1;
}
