#ifndef GLOBALS_H
#define GLOBALS_H

#include <pthread.h>
#include <signal.h>
#include <sys/types.h>

#include "../osxiec.h"

#define MAX_BACKGROUND_THREADS 32
#define MAX_SCHEDULED_TASKS 32
#define MAX_HISTORY_LEN 100
#define MAX_COMMAND_LEN 1024
#define MAX_LINE_LEN 1024
#define DEBUG_NONE 0
#define DEBUG_STEP 1
#define DEBUG_BREAK 2
#define PORT 3000
#define SHARED_FOLDER_PATH "/Volumes/SharedContainer"
#define CPU_USAGE_THRESHOLD 80.0
#define MEMORY_USAGE_THRESHOLD 80.0
#define MIN_CPU_PRIORITY -20
#define MAX_MEMORY_LIMIT 2147483648

extern int port;
extern int debug_mode;
extern char *breakpoint;
extern ContainerState container_state;

typedef struct {
  char commands[MAX_HISTORY_LEN][MAX_COMMAND_LEN];
  int count;
  int current;
} CommandHistory;

extern CommandHistory history;
extern volatile sig_atomic_t stop_thread;
extern volatile sig_atomic_t should_exit;
extern volatile sig_atomic_t attach_interrupted;

typedef struct {
  pthread_t thread;
  pid_t pid;
  char command[MAX_COMMAND_LEN];
  int is_running;
  int is_paused;
  int exit_code;
  char output[4096];
  pthread_mutex_t output_mutex;
  pthread_cond_t pause_cond;
  char container_root[MAX_PATH_LEN];
  time_t start_time;
} BackgroundTask;

typedef struct {
  BackgroundTask tasks[MAX_BACKGROUND_THREADS];
  int task_count;
  pthread_mutex_t tasks_mutex;
} BackgroundTaskManager;

extern BackgroundTaskManager bg_manager;

typedef struct {
  char command[MAX_COMMAND_LEN];
  time_t scheduled_time;
} ScheduledTask;

extern ScheduledTask scheduled_tasks[MAX_SCHEDULED_TASKS];
extern int num_scheduled_tasks;

// Maximum number of descendant processes the reaper can track at once. This
// includes the processes we spawn directly plus any forked children the
// kernel reports to us through NOTE_TRACK.
#define REAPER_MAX_PIDS 256

// State for the kqueue-based process reaper (see reaper.c). The reaper watches
// every process the container spawns via EVFILT_PROC and tears the whole tree
// down when the container exits, so background tasks and double-forked daemons
// cannot leak past the container's lifetime.
typedef struct {
  int kq;                         // kqueue descriptor, -1 when inactive
  pthread_t thread;               // background reaper loop
  volatile sig_atomic_t running;  // cleared to stop the loop
  pthread_mutex_t lock;           // guards pids/is_leader/count
  pid_t pids[REAPER_MAX_PIDS];    // tracked descendants
  int is_leader[REAPER_MAX_PIDS]; // 1 if pid leads its own process group
  int count;
} ProcessReaper;

extern ProcessReaper reaper;

#endif
