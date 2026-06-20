#include "globals.h"

int port = PORT;
ContainerState container_state = {0};
CommandHistory history = {.count = 0, .current = 0};
int debug_mode = DEBUG_NONE;
char *breakpoint = NULL;
volatile sig_atomic_t stop_thread = 0;
volatile sig_atomic_t should_exit = 0;
volatile sig_atomic_t attach_interrupted = 0;
BackgroundTaskManager bg_manager = {.task_count = 0, .tasks_mutex = PTHREAD_MUTEX_INITIALIZER};
ScheduledTask scheduled_tasks[MAX_SCHEDULED_TASKS];
int num_scheduled_tasks = 0;
ProcessReaper reaper = {.kq = -1, .running = 0, .count = 0};
