#include "log.h"
#include <execinfo.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static FILE *log_fp = NULL;
// Raw descriptor mirroring log_fp, kept so the crash handler can dump a stack
// trace without touching async-signal-unsafe stdio.
static int log_fd = -1;
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

static const char *level_name(LogLevel level) {
  switch (level) {
  case LOG_DEBUG:
    return "DEBUG";
  case LOG_INFO:
    return "INFO";
  case LOG_WARN:
    return "WARN";
  case LOG_ERROR:
    return "ERROR";
  case LOG_FATAL:
    return "FATAL";
  }
  return "INFO";
}

static void iso_timestamp(char *buf, size_t n) {
  time_t now = time(NULL);
  struct tm tm_utc;
  gmtime_r(&now, &tm_utc);
  strftime(buf, n, "%Y-%m-%dT%H:%M:%SZ", &tm_utc);
}

int container_log_init(const char *container_root) {
  pthread_mutex_lock(&log_mutex);
  if (log_fp != NULL) { // already initialized
    pthread_mutex_unlock(&log_mutex);
    return 0;
  }

  // Best-effort: make sure var/log exists before opening the file.
  char path[MAX_PATH_LEN];
  snprintf(path, sizeof(path), "%s/var", container_root);
  mkdir(path, 0755);
  snprintf(path, sizeof(path), "%s/var/log", container_root);
  mkdir(path, 0755);

  snprintf(path, sizeof(path), "%s/var/log/log.txt", container_root);
  log_fp = fopen(path, "a");
  if (log_fp == NULL) {
    pthread_mutex_unlock(&log_mutex);
    return -1;
  }
  setvbuf(log_fp, NULL, _IOLBF, 0); // line-buffered so logs survive a crash
  log_fd = fileno(log_fp);
  pthread_mutex_unlock(&log_mutex);

  container_log(LOG_INFO, "logging", "container log opened at %s", path);
  return 0;
}

void container_log(LogLevel level, const char *category, const char *fmt, ...) {
  if (log_fp == NULL)
    return;

  char ts[32];
  iso_timestamp(ts, sizeof(ts));

  // The periodic logger thread is torn down with pthread_cancel(); disable
  // cancellation around the locked section so it can never be cancelled while
  // holding log_mutex (which would deadlock container_log_close()).
  int oldstate;
  pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &oldstate);
  pthread_mutex_lock(&log_mutex);
  fprintf(log_fp, "%s [%-5s] [%s] ", ts, level_name(level),
          category ? category : "-");
  va_list ap;
  va_start(ap, fmt);
  vfprintf(log_fp, fmt, ap);
  va_end(ap);
  fputc('\n', log_fp);
  fflush(log_fp);
  pthread_mutex_unlock(&log_mutex);
  pthread_setcancelstate(oldstate, NULL);
}

void log_command_exec(const char *command) {
  container_log(LOG_INFO, "exec", "command=\"%s\"", command);
}

void log_command_result(const char *command, int wait_status) {
  if (WIFEXITED(wait_status)) {
    int code = WEXITSTATUS(wait_status);
    container_log(code == 0 ? LOG_INFO : LOG_WARN, "exec",
                  "command=\"%s\" exited code=%d", command, code);
  } else if (WIFSIGNALED(wait_status)) {
    int sig = WTERMSIG(wait_status);
    container_log(LOG_WARN, "exec", "command=\"%s\" killed by signal %d (%s)",
                  command, sig, strsignal(sig));
  }
}

void log_resource_usage(const ContainerConfig *config) {
  struct rusage usage;
  if (getrusage(RUSAGE_SELF, &usage) != 0)
    return;

  long mem = usage.ru_maxrss; // bytes on macOS
  double cpu = get_cpu_usage();

  if (config != NULL) {
    double mem_pct = config->memory_soft_limit > 0
                         ? (mem * 100.0) / config->memory_soft_limit
                         : 0.0;
    container_log(LOG_INFO, "stats",
                  "cpu=%.2f%% mem=%ld/%ld bytes (%.2f%%) cpu_prio=%d "
                  "majflt=%ld nvcsw=%ld nivcsw=%ld",
                  cpu, mem, config->memory_soft_limit, mem_pct,
                  config->cpu_priority, usage.ru_majflt, usage.ru_nvcsw,
                  usage.ru_nivcsw);
  } else {
    container_log(LOG_INFO, "stats", "cpu=%.2f%% mem=%ld bytes", cpu, mem);
  }
}

void log_crash(int sig) {
  // Invoked from a signal handler, so keep to async-signal-safe primitives:
  // write() directly to the log descriptor and let backtrace_symbols_fd emit
  // the frames (it is documented as safe to call from a handler).
  if (log_fd < 0)
    return;

  char header[96];
  int n = snprintf(header, sizeof(header),
                   "\n*** container crashed: fatal signal %d ***\n", sig);
  if (n > 0)
    (void)!write(log_fd, header, (size_t)n);

  void *frames[64];
  int count = backtrace(frames, 64);
  backtrace_symbols_fd(frames, count, log_fd);
  fsync(log_fd);
}

void container_log_close(void) {
  pthread_mutex_lock(&log_mutex);
  if (log_fp != NULL) {
    fflush(log_fp);
    fclose(log_fp);
    log_fp = NULL;
    log_fd = -1;
  }
  pthread_mutex_unlock(&log_mutex);
}
