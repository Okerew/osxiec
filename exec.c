#include "globals/globals.h"
#include "log/log.h"
#include "osxiec.h"
#include "osxiec_script/osxiec_script.h"
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <readline/readline.h>
#include <regex.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

// Run the interactive "debug>" prompt until the user resumes execution
// (continue/step). break/print/help keep the prompt open.
void debug_prompt_loop(void) {
  char *debug_cmd;
  while ((debug_cmd = readline("debug> ")) != NULL) {
    int resume = handle_debug_command(debug_cmd);
    free(debug_cmd);
    if (resume)
      break;
  }
}

// Entered from the container shell when the user types "debug". Drops straight
// into the debugger prompt instead of merely arming a flag, so a single
// "debug" command takes effect immediately.
void enter_debug_mode(void) {
  if (debug_mode == DEBUG_NONE)
    debug_mode = DEBUG_STEP;
  printf("Entered debug mode. Type 'help' for debug commands, "
         "'continue' to resume.\n");
  debug_prompt_loop();
}

void execute_command(const char *command, const char *container_root) {
  if (command == NULL || strlen(command) == 0) {
    fprintf(stderr, "Error: Empty command\n");
    return;
  }

  if (debug_mode == DEBUG_STEP || (debug_mode == DEBUG_BREAK && breakpoint &&
                                   strstr(command, breakpoint))) {
    printf("Debugger: Paused at command: %s\n", command);
    debug_prompt_loop();
  }

  printf("Executing: %s\n", command);
  strncpy(container_state.last_executed_command, command, MAX_COMMAND_LEN - 1);
  container_state.last_executed_command[MAX_COMMAND_LEN - 1] = '\0';

  if (strncmp(command, "cd ", 3) == 0) {
    const char *new_dir = command + 3;

    if (container_root != NULL) {
      const char shared_folder_path[] = "/Volumes/SharedContainer";
      char current_path[PATH_MAX];
      if (getcwd(current_path, sizeof(current_path)) == NULL) {
        perror("Failed to get current directory");
        return;
      }
      if (is_subpath(new_dir, container_root) ||
          is_subpath(new_dir, shared_folder_path) ||
          (is_subpath(current_path, shared_folder_path) &&
           strcmp(new_dir, container_root) == 0)) {
        if (chdir(new_dir) == 0) {
          getcwd(container_state.current_directory, MAX_PATH_LEN);
          printf("Changed directory to: %s\n",
                 container_state.current_directory);
        } else {
          perror("Failed to change directory");
        }
      } else {
        fprintf(stderr, "Error: Cannot change directory outside of the "
                        "container or shared folder.\n");
      }
    } else {
      if (chdir(new_dir) == 0) {
        getcwd(container_state.current_directory, MAX_PATH_LEN);
        printf("Changed directory to: %s\n", container_state.current_directory);
      } else {
        perror("Failed to change directory");
      }
    }
    return;
  }

  char *args[MAX_COMMAND_LEN / 2 + 1];
  char *command_copy = strdup(command);
  if (command_copy == NULL) {
    perror("Failed to allocate memory for command");
    return;
  }

  char *token = strtok(command_copy, " ");
  int i = 0;
  while (token != NULL && i < MAX_COMMAND_LEN / 2) {
    args[i++] = token;
    token = strtok(NULL, " ");
  }
  args[i] = NULL;

  pid_t pid;
  int status;
  posix_spawn_file_actions_t actions;
  posix_spawnattr_t attr;

  if (posix_spawn_file_actions_init(&actions) != 0) {
    perror("posix_spawn_file_actions_init failed");
    free(command_copy);
    return;
  }

  if (posix_spawnattr_init(&attr) != 0) {
    perror("posix_spawnattr_init failed");
    posix_spawn_file_actions_destroy(&actions);
    free(command_copy);
    return;
  }

  extern char **environ;
  char **new_environ = environ;
  char *custom_environ[1024];
  int env_count = 0;

  if (container_root != NULL) {
    for (char **env = environ; *env && env_count < 1000; env++) {
      if (strncmp(*env, "PWD=", 4) != 0 && strncmp(*env, "HOME=", 5) != 0 &&
          strncmp(*env, "OLDPWD=", 7) != 0 &&
          strncmp(*env, "TMPDIR=", 7) != 0) {
        custom_environ[env_count++] = *env;
      }
    }

    static char pwd_env[MAX_PATH_LEN + 4];
    static char home_env[MAX_PATH_LEN + 5];
    static char root_env[MAX_PATH_LEN + 15];
    static char tmpdir_env[MAX_PATH_LEN + 8];
    static char oldpwd_env[MAX_PATH_LEN + 8];
    static char path_env[MAX_PATH_LEN * 2];

    char current_dir[PATH_MAX];
    if (getcwd(current_dir, sizeof(current_dir)) != NULL) {
      if (strncmp(current_dir, container_root, strlen(container_root)) == 0) {
        const char *relative_path = current_dir + strlen(container_root);
        if (strlen(relative_path) == 0) {
          relative_path = "/";
        }
        snprintf(pwd_env, sizeof(pwd_env), "PWD=%s", relative_path);
      } else {
        snprintf(pwd_env, sizeof(pwd_env), "PWD=/");
      }
    } else {
      snprintf(pwd_env, sizeof(pwd_env), "PWD=/");
    }

    snprintf(home_env, sizeof(home_env), "HOME=/root");
    snprintf(root_env, sizeof(root_env), "CONTAINER_ROOT=%s", container_root);
    snprintf(tmpdir_env, sizeof(tmpdir_env), "TMPDIR=/tmp");
    snprintf(oldpwd_env, sizeof(oldpwd_env), "OLDPWD=/");
    snprintf(path_env, sizeof(path_env),
             "PATH=/bin:/usr/bin:/usr/local/bin:/sbin:/usr/sbin:"
             "/opt/homebrew/bin");

    custom_environ[env_count++] = pwd_env;
    custom_environ[env_count++] = home_env;
    custom_environ[env_count++] = root_env;
    custom_environ[env_count++] = tmpdir_env;
    custom_environ[env_count++] = oldpwd_env;
    custom_environ[env_count++] = path_env;
    custom_environ[env_count] = NULL;

    new_environ = custom_environ;
  }

  char *executable_path = args[0];
  char translated_executable[MAX_PATH_LEN];

  if (container_root != NULL && args[0][0] != '/' && args[0][0] != '.') {
    const char *search_paths[] = {"/bin",  "/usr/bin",  "/usr/local/bin",
                                  "/sbin", "/usr/sbin", "/opt/homebrew/bin"};

    for (int j = 0; j < 6; j++) {
      snprintf(translated_executable, sizeof(translated_executable), "%s%s/%s",
               container_root, search_paths[j], args[0]);
      if (access(translated_executable, X_OK) == 0) {
        executable_path = translated_executable;
        break;
      }
    }
  }

  char original_cwd[PATH_MAX];
  getcwd(original_cwd, sizeof(original_cwd));

  int ret =
      posix_spawnp(&pid, executable_path, &actions, &attr, args, new_environ);

  if (ret == 0) {
    // Register the foreground command for exit accounting. We leave it in the
    // container's process group (no setpgid) so interactive programs keep
    // access to the terminal; it is reaped synchronously by the waitpid below,
    // so it is normally gone from the reaper's table well before shutdown.
    reaper_register(pid, 0);
    if (waitpid(pid, &status, 0) != -1) {
      if (WIFEXITED(status)) {
        int exit_status = WEXITSTATUS(status);
        if (exit_status != 0) {
          printf("Child process exited with status %d\n", exit_status);
        }
      } else if (WIFSIGNALED(status)) {
        printf("Child process terminated by signal %d\n", WTERMSIG(status));
      }
      log_command_result(command, status);
    } else {
      perror("Error waiting for child process");
    }
  } else {
    fprintf(stderr, "posix_spawnp failed: %s\n", strerror(ret));
    container_log(LOG_ERROR, "exec", "failed to spawn \"%s\": %s", command,
                  strerror(ret));
  }

  posix_spawn_file_actions_destroy(&actions);
  posix_spawnattr_destroy(&attr);
  free(command_copy);
}

void handle_script_command(const char *script_content) {
  execute_script(script_content);
}

void handle_script_file(const char *filename) { execute_script_file(filename); }

void *background_command_thread(void *arg) {
  BackgroundTask *task = (BackgroundTask *)arg;

  if (chdir(task->container_root) != 0) {
    snprintf(task->output, sizeof(task->output),
             "Failed to change to container directory\n");
    task->is_running = 0;
    return NULL;
  }

  int pipefd[2];
  if (pipe(pipefd) == -1) {
    snprintf(task->output, sizeof(task->output), "Failed to create pipe\n");
    task->is_running = 0;
    return NULL;
  }

  pid_t pid = fork();
  if (pid == -1) {
    snprintf(task->output, sizeof(task->output), "Fork failed\n");
    task->is_running = 0;
    return NULL;
  }

  if (pid == 0) { // Child process
    // Lead our own process group so the reaper can take down the whole
    // background-task subtree with a single killpg() at container teardown.
    setpgid(0, 0);
    close(pipefd[0]);
    dup2(pipefd[1], STDOUT_FILENO);
    dup2(pipefd[1], STDERR_FILENO);
    close(pipefd[1]);

    char *args[] = {"/bin/sh", "-c", task->command, NULL};
    execvp(args[0], args);
    exit(127);
  }

  // Store the process ID in the task structure
  task->pid = pid;

  // Register the group leader with the reaper for guaranteed cleanup.
  reaper_register(pid, 1);

  close(pipefd[1]);

  char buffer[1024];
  ssize_t n;

  while ((n = read(pipefd[0], buffer, sizeof(buffer) - 1)) > 0) {
    buffer[n] = '\0';
    pthread_mutex_lock(&task->output_mutex);
    while (task->is_paused) {
      pthread_cond_wait(&task->pause_cond, &task->output_mutex);
    }
    strncat(task->output, buffer,
            sizeof(task->output) - strlen(task->output) - 1);
    pthread_mutex_unlock(&task->output_mutex);
  }

  close(pipefd[0]);

  int status;
  waitpid(pid, &status, 0);
  task->exit_code = WEXITSTATUS(status);
  task->is_running = 0;
  return NULL;
}

// Modify start_background_task to initialize new fields
int start_background_task(const char *command, const char *container_root) {
  pthread_mutex_lock(&bg_manager.tasks_mutex);

  if (bg_manager.task_count >= MAX_BACKGROUND_THREADS) {
    pthread_mutex_unlock(&bg_manager.tasks_mutex);
    return -1;
  }

  int task_id = bg_manager.task_count++;
  BackgroundTask *task = &bg_manager.tasks[task_id];

  memset(task, 0, sizeof(BackgroundTask));
  strncpy(task->command, command, MAX_COMMAND_LEN - 1);
  strncpy(task->container_root, container_root, MAX_PATH_LEN - 1);
  task->is_running = 1;
  task->is_paused = 0;
  task->pid = 0;
  task->start_time = time(NULL);
  pthread_mutex_init(&task->output_mutex, NULL);
  pthread_cond_init(&task->pause_cond, NULL);

  if (pthread_create(&task->thread, NULL, background_command_thread, task) !=
      0) {
    bg_manager.task_count--;
    pthread_mutex_unlock(&bg_manager.tasks_mutex);
    return -1;
  }

  pthread_mutex_unlock(&bg_manager.tasks_mutex);
  return task_id;
}

void pause_background_tasks() {
  pthread_mutex_lock(&bg_manager.tasks_mutex);
  for (int i = 0; i < bg_manager.task_count; i++) {
    BackgroundTask *task = &bg_manager.tasks[i];
    if (task->is_running) {
      pthread_mutex_lock(&task->output_mutex);
      task->is_paused = 1;
      pthread_mutex_unlock(&task->output_mutex);
    }
  }
  pthread_mutex_unlock(&bg_manager.tasks_mutex);
}

void unpause_background_tasks() {
  pthread_mutex_lock(&bg_manager.tasks_mutex);
  for (int i = 0; i < bg_manager.task_count; i++) {
    BackgroundTask *task = &bg_manager.tasks[i];
    if (task->is_running) {
      pthread_mutex_lock(&task->output_mutex);
      task->is_paused = 0;
      pthread_cond_signal(&task->pause_cond);
      pthread_mutex_unlock(&task->output_mutex);
    }
  }
  pthread_mutex_unlock(&bg_manager.tasks_mutex);
}

void wait_background_task(int task_id) {
  if (task_id < 0 || task_id >= bg_manager.task_count) {
    printf("Invalid task ID\n");
    return;
  }

  BackgroundTask *task = &bg_manager.tasks[task_id];
  pthread_join(task->thread, NULL);

  printf("\nBackground task %d completed\n", task_id);
  printf("Command: %s\n", task->command);
  printf("Exit code: %d\n", task->exit_code);
  printf("Output:\n%s\n", task->output);
}

void show_background_tasks() {
  pthread_mutex_lock(&bg_manager.tasks_mutex);

  printf("\nBackground Tasks:\n");
  printf("%-4s %-8s %-10s %-8s %-20s %s\n", "ID", "PID", "STATUS", "RUNTIME",
         "STARTED", "COMMAND");
  printf("---------------------------------------------------------------------"
         "-----------\n");

  time_t current_time = time(NULL);
  int found = 0;

  for (int i = 0; i < bg_manager.task_count; i++) {
    BackgroundTask *task = &bg_manager.tasks[i];
    if (task->is_running) {
      found = 1;
      const char *status = task->is_paused ? "PAUSED" : "RUNNING";

      // Calculate runtime
      time_t runtime = current_time - task->start_time;
      char runtime_str[32];
      snprintf(runtime_str, sizeof(runtime_str), "%02ld:%02ld:%02ld",
               runtime / 3600, (runtime % 3600) / 60, runtime % 60);

      // Format start time
      char start_time_str[32];
      strftime(start_time_str, sizeof(start_time_str), "%H:%M:%S",
               localtime(&task->start_time));

      printf("%-4d %-8d %-10s %-8s %-20s %s\n", i, task->pid, status,
             runtime_str, start_time_str, task->command);
    }
  }

  if (!found) {
    printf("No running background tasks\n");
  }
  printf("---------------------------------------------------------------------"
         "-----------\n");

  pthread_mutex_unlock(&bg_manager.tasks_mutex);
}

void start_network_thread(pthread_t network_thread, int network_thread_active) {
  if (network_thread_active) {
    printf("Network listener is already running\n");
    return;
  }

  if (pthread_create(&network_thread, NULL,
                     (void *(*)(void *))start_network_listener, NULL) != 0) {
    perror("Failed to create network listener thread");
  } else {
    network_thread_active = 1;
    printf("Network listener started successfully\n");
  }
}

void stop_network_thread(pthread_t network_thread, int network_thread_active) {
  if (!network_thread_active) {
    printf("Network listener is not running\n");
    return;
  }

  pthread_cancel(network_thread);
  pthread_join(network_thread, NULL);
  network_thread_active = 0;
  printf("Network listener stopped successfully\n");
}

void trace_command(const char *command, const char *container_root) {
  printf("Starting command tracing for: %s\n", command);
  char trace_log_path[MAX_PATH_LEN];
  snprintf(trace_log_path, sizeof(trace_log_path), "%s/var/log/trace_log.txt",
           container_root);

  // Create a unique wrapper script
  char wrapper_path[MAX_PATH_LEN];
  snprintf(wrapper_path, sizeof(wrapper_path), "%s/trace_wrapper_%d.sh",
           container_root, (int)time(NULL));

  FILE *wrapper = fopen(wrapper_path, "w");
  if (!wrapper) {
    perror("Failed to create wrapper script");
    return;
  }

  // Create a script that will record execution info without requiring
  // privileges
  fprintf(wrapper, "#!/bin/sh\n");
  fprintf(wrapper, "echo \"=== Command Trace: %s ===\" > %s\n", command,
          trace_log_path);
  fprintf(wrapper, "echo \"Started at $(date)\" >> %s\n", trace_log_path);
  fprintf(wrapper, "echo \"Current directory: $(pwd)\" >> %s\n",
          trace_log_path);
  fprintf(wrapper, "echo \"Environment variables:\" >> %s\n", trace_log_path);
  fprintf(wrapper, "env | sort >> %s\n", trace_log_path);
  fprintf(wrapper, "echo \"\\nCommand output:\" >> %s\n", trace_log_path);
  fprintf(wrapper, "echo \"-------------------\" >> %s\n", trace_log_path);
  fprintf(wrapper, "# Run the command and capture timing info\n");
  fprintf(wrapper, "START=$(date +%%s.%%N)\n");
  fprintf(wrapper, "{ time %s ; } 2>&1 | tee -a %s\n", command, trace_log_path);
  fprintf(wrapper, "END=$(date +%%s.%%N)\n");
  fprintf(wrapper,
          "echo \"\\nExecution time: $(echo \"$END - $START\" | bc) seconds\" "
          ">> %s\n",
          trace_log_path);
  fprintf(wrapper, "echo \"Finished at $(date)\" >> %s\n", trace_log_path);
  fprintf(wrapper, "echo \"Exit status: $?\" >> %s\n", trace_log_path);
  fprintf(wrapper, "echo \"-------------------\" >> %s\n", trace_log_path);

  // Replace ps command with /proc inspection for memory usage
  fprintf(wrapper, "echo \"Memory usage after execution:\" >> %s\n",
          trace_log_path);
  fprintf(wrapper, "echo \"PID    COMMAND    RSS    VSZ\" >> %s\n",
          trace_log_path);
  fprintf(wrapper, "for pid in $(pgrep -f \"%s\"); do\n", command);
  fprintf(wrapper, "  if [ -d \"/proc/$pid\" ]; then\n");
  fprintf(wrapper,
          "    cmd=$(cat /proc/$pid/cmdline | tr '\\0' ' ' | head -c 30)\n");
  fprintf(wrapper, "    if [ -f \"/proc/$pid/status\" ]; then\n");
  fprintf(wrapper,
          "      rss=$(grep VmRSS /proc/$pid/status | awk '{print $2}')\n");
  fprintf(wrapper,
          "      vsz=$(grep VmSize /proc/$pid/status | awk '{print $2}')\n");
  fprintf(wrapper,
          "      echo \"$pid    $cmd    ${rss:-0}    ${vsz:-0}\" >> %s\n",
          trace_log_path);
  fprintf(wrapper, "    fi\n");
  fprintf(wrapper, "  fi\n");
  fprintf(wrapper, "done\n");

  // Use lsof for file descriptors since it works
  fprintf(wrapper, "echo \"File descriptors after execution:\" >> %s\n",
          trace_log_path);
  fprintf(wrapper, "for pid in $(pgrep -f \"%s\"); do\n", command);
  fprintf(wrapper, "  echo \"File descriptors for PID $pid:\" >> %s\n",
          trace_log_path);
  fprintf(wrapper,
          "  lsof -p $pid 2>/dev/null | head -20 >> %s 2>&1 || echo \"No file "
          "descriptor info available\" >> %s\n",
          trace_log_path, trace_log_path);
  fprintf(wrapper, "done\n");

  fclose(wrapper);
  chmod(wrapper_path, 0755);

  printf("Executing command with tracing...\n");
  printf("----------------\n");

  // Execute the wrapper script
  system(wrapper_path);

  // Read and display the log
  FILE *log = fopen(trace_log_path, "r");
  if (log) {
    char buffer[1024];
    while (fgets(buffer, sizeof(buffer), log)) {
      printf("%s", buffer);
    }
    fclose(log);
  }

  // Clean up the wrapper script
  unlink(wrapper_path);

  printf("----------------\n");
  printf("Trace completed. Log saved to %s\n", trace_log_path);
}

void trace_background_process(int process_id, const char *container_root) {
  // First, check if the process ID exists and is a running background task
  int valid_task = 0;
  // Iterate through the background tasks
  for (int i = 0; i < bg_manager.task_count; i++) {
    BackgroundTask *task = &bg_manager.tasks[i];
    if (task->pid == process_id && task->is_running == 1) {
      valid_task = 1;
      break;
    }
  }
  if (!valid_task) {
    printf("Error: Process ID %d is not a valid running background task\n",
           process_id);
    return;
  }

  printf("Starting trace for background process ID: %d\n", process_id);
  char trace_log_path[MAX_PATH_LEN];
  snprintf(trace_log_path, sizeof(trace_log_path),
           "%s/var/log/proc_trace_%d.txt", container_root, process_id);

  // Create a monitor script that samples the process periodically
  char monitor_path[MAX_PATH_LEN];
  snprintf(monitor_path, sizeof(monitor_path), "%s/var/log/proc_monitor_%d.sh",
           container_root, process_id);

  FILE *monitor = fopen(monitor_path, "w");
  if (!monitor) {
    perror("Failed to create monitor script");
    return;
  }

  // Create a script that will monitor the process without requiring privileges
  fprintf(monitor, "#!/bin/sh\n");
  fprintf(monitor, "echo \"=== Process Trace: PID %d ===\" > %s\n", process_id,
          trace_log_path);
  fprintf(monitor, "echo \"Started monitoring at $(date)\" >> %s\n",
          trace_log_path);

  // Use /proc filesystem instead of ps for process info
  fprintf(monitor, "echo \"\\nInitial process info:\" >> %s\n", trace_log_path);
  fprintf(monitor,
          "echo \"PID PPID COMMAND CPU MEM RSS VSZ STATE START TIME\" >> %s\n",
          trace_log_path);
  fprintf(monitor, "if [ -d \"/proc/%d\" ]; then\n", process_id);
  fprintf(
      monitor,
      "  cmd=$(cat /proc/%d/cmdline 2>/dev/null | tr '\\0' ' ' | head -c 30)\n",
      process_id);
  fprintf(monitor,
          "  ppid=$(cat /proc/%d/stat 2>/dev/null | awk '{print $4}')\n",
          process_id);
  fprintf(monitor,
          "  state=$(cat /proc/%d/stat 2>/dev/null | awk '{print $3}')\n",
          process_id);
  fprintf(monitor, "  if [ -f \"/proc/%d/status\" ]; then\n", process_id);
  fprintf(
      monitor,
      "    rss=$(grep VmRSS /proc/%d/status 2>/dev/null | awk '{print $2}')\n",
      process_id);
  fprintf(
      monitor,
      "    vsz=$(grep VmSize /proc/%d/status 2>/dev/null | awk '{print $2}')\n",
      process_id);
  fprintf(monitor, "  fi\n");
  fprintf(monitor, "  start=$(stat -c %%Y /proc/%d 2>/dev/null)\n", process_id);
  fprintf(monitor, "  if [ -n \"$start\" ]; then\n");
  fprintf(monitor, "    start_time=$(date -d @$start '+%%H:%%M' 2>/dev/null || "
                   "date -r $start '+%%H:%%M' 2>/dev/null)\n");
  fprintf(monitor, "  else\n");
  fprintf(monitor, "    start_time=\"unknown\"\n");
  fprintf(monitor, "  fi\n");
  fprintf(monitor, "  uptime=$(cut -d' ' -f1 /proc/uptime 2>/dev/null)\n");
  fprintf(monitor, "  if [ -f \"/proc/%d/stat\" ]; then\n", process_id);
  fprintf(monitor,
          "    utime=$(cat /proc/%d/stat 2>/dev/null | awk '{print $14}')\n",
          process_id);
  fprintf(monitor,
          "    stime=$(cat /proc/%d/stat 2>/dev/null | awk '{print $15}')\n",
          process_id);
  fprintf(monitor, "    if [ -n \"$utime\" ] && [ -n \"$stime\" ]; then\n");
  fprintf(monitor, "      total_time=$((utime + stime))\n");
  fprintf(monitor,
          "      clock_ticks=$(getconf CLK_TCK 2>/dev/null || echo 100)\n");
  fprintf(monitor, "      total_time_sec=$(echo \"scale=2; $total_time / "
                   "$clock_ticks\" | bc 2>/dev/null)\n");
  fprintf(monitor, "      echo \"$total_time_sec seconds CPU time\" >> %s\n",
          trace_log_path);
  fprintf(monitor, "    fi\n");
  fprintf(monitor, "  fi\n");
  fprintf(
      monitor,
      "  echo \"%d ${ppid:-?} ${cmd:-unknown} ${cpu:-?} ${mem:-?} ${rss:-0} "
      "${vsz:-0} ${state:-?} ${start_time:-?} ${total_time_sec:-?}\" >> %s\n",
      process_id, trace_log_path);
  fprintf(monitor, "else\n");
  fprintf(monitor,
          "  echo \"Process %d not found in /proc filesystem\" >> %s\n",
          process_id, trace_log_path);
  fprintf(monitor, "fi\n");

  fprintf(
      monitor,
      "echo \"\\nMonitoring process activity (Press Ctrl+C to stop):\" >> %s\n",
      trace_log_path);
  fprintf(monitor, "echo \"-------------------\" >> %s\n", trace_log_path);
  fprintf(monitor, "while kill -0 %d 2>/dev/null; do\n", process_id);
  fprintf(monitor, "  echo \"\\n[$(date)] Process snapshot:\" >> %s\n",
          trace_log_path);

  // Periodic process monitoring without ps
  fprintf(monitor, "  if [ -d \"/proc/%d\" ]; then\n", process_id);
  fprintf(monitor, "    echo \"Process status:\" >> %s\n", trace_log_path);
  fprintf(monitor,
          "    cat /proc/%d/status 2>/dev/null | grep -E "
          "'Name|State|Pid|PPid|VmRSS|VmSize|Threads' >> %s 2>&1 || echo \"No "
          "status info available\" >> %s\n",
          process_id, trace_log_path, trace_log_path);
  fprintf(monitor, "  fi\n");

  // Use lsof for file and socket information
  fprintf(monitor, "  echo \"Open files and sockets:\" >> %s\n",
          trace_log_path);
  fprintf(monitor,
          "  lsof -p %d 2>/dev/null | head -20 >> %s 2>&1 || echo \"No file "
          "descriptor info available\" >> %s\n",
          process_id, trace_log_path, trace_log_path);

  // Check for child processes using /proc
  fprintf(monitor, "  echo \"Child processes:\" >> %s\n", trace_log_path);
  fprintf(monitor, "  for cpid in /proc/[0-9]*/stat; do\n");
  fprintf(monitor, "    if [ -f \"$cpid\" ]; then\n");
  fprintf(monitor, "      ppid=$(cat $cpid 2>/dev/null | awk '{print $4}')\n");
  fprintf(monitor, "      if [ \"$ppid\" = \"%d\" ]; then\n", process_id);
  fprintf(monitor, "        pid=$(basename $(dirname $cpid))\n");
  fprintf(monitor, "        cmd=$(cat /proc/$pid/cmdline 2>/dev/null | tr "
                   "'\\0' ' ' | head -c 30)\n");
  fprintf(monitor, "        echo \"$pid $ppid ${cmd:-unknown}\" >> %s\n",
          trace_log_path);
  fprintf(monitor, "      fi\n");
  fprintf(monitor, "    fi\n");
  fprintf(monitor, "  done\n");

  fprintf(monitor, "  sleep 1\n");
  fprintf(monitor, "done\n");
  fprintf(
      monitor,
      "echo \"\\nProcess %d has terminated or is no longer visible\" >> %s\n",
      process_id, trace_log_path);
  fprintf(monitor, "echo \"Monitoring stopped at $(date)\" >> %s\n",
          trace_log_path);

  fclose(monitor);
  chmod(monitor_path, 0755);

  printf("Starting process monitoring. Press Ctrl+C to stop.\n");
  printf("The log will be saved to %s\n", trace_log_path);

  // Run the monitor script
  char monitor_cmd[MAX_COMMAND_LEN];
  snprintf(monitor_cmd, sizeof(monitor_cmd), "%s &", monitor_path);
  system(monitor_cmd);

  printf("Monitoring started in background. Use 'ls -la %s' to see the log "
         "file.\n",
         trace_log_path);
  printf("You can view the log file at any time with 'cat %s'\n",
         trace_log_path);
}

void handle_attach_interrupt(int sig) { attach_interrupted = 1; }

void live_process_inspection(const char *container_root) {
  printf("\033[2J\033[H"); // Clear screen and move cursor to top
  printf("Live Process Inspection (Press 'q' to exit)\n");
  printf("%-6s %-10s %-5s %-5s %-10s %-10s %s\n", "PID", "USER", "CPU%", "MEM%",
         "VSZ", "RSS", "COMMAND");

  set_terminal_raw_mode();

  int running = 1;
  while (running) {
    char ps_command[MAX_COMMAND_LEN];
    snprintf(ps_command, sizeof(ps_command),
             "ps -eo pid,user,pcpu,pmem,vsz,rss,comm | grep -v grep");

    FILE *pipe = popen(ps_command, "r");
    if (!pipe) {
      perror("Failed to run ps command");
      break;
    }

    // Skip header line from ps output
    char buffer[1024];
    fgets(buffer, sizeof(buffer), pipe);

    printf("\033[3;1H"); // Move cursor to line 3
    printf("\033[J");    // Clear from cursor to end of screen

    int line = 0;
    while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
      // Filter processes that belong to the container namespace
      if (strstr(buffer, container_root) ||
          1) { // Always true for now, implement proper filtering if needed
        printf("%-80s\n", buffer);
        line++;
        if (line > 20)
          break; // Limit display to 20 processes
      }
    }

    pclose(pipe);

    // Poll for keypress
    fd_set fds;
    struct timeval tv;
    FD_ZERO(&fds);
    FD_SET(STDIN_FILENO, &fds);
    tv.tv_sec = 1;
    tv.tv_usec = 0;

    int result = select(STDIN_FILENO + 1, &fds, NULL, NULL, &tv);
    if (result > 0) {
      char c = getchar();
      if (c == 'q' || c == 'Q') {
        running = 0;
      }
    }
  }

  set_terminal_canonical_mode();
  printf("\nExiting process inspector\n");
}

void attach_to_background_task(int task_id) {
  if (task_id < 0 || task_id >= MAX_BACKGROUND_THREADS) {
    printf("Invalid task ID\n");
    return;
  }

  int valid_task = 0;
  for (int i = 0; i < bg_manager.task_count; i++) {
    if (i == task_id && bg_manager.tasks[i].is_running == 1) {
      valid_task = 1;
      break;
    }
  }

  if (!valid_task) {
    printf("No running task with ID %d\n", task_id);
    return;
  }

  BackgroundTask *task = &bg_manager.tasks[task_id];
  printf("Attaching to task %d (PID %d): %s\n", task_id, task->pid,
         task->command);
  printf("Press Ctrl+C to detach (this will NOT terminate the process)\n");

  // Set up signal handler for Ctrl+C
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = handle_attach_interrupt;
  sigaction(SIGINT, &sa, NULL);

  set_terminal_raw_mode();

  // Print current output
  pthread_mutex_lock(&task->output_mutex);
  printf("%s", task->output);
  pthread_mutex_unlock(&task->output_mutex);

  int running = 1;
  char last_seen[4096] = {0};
  strncpy(last_seen, task->output, sizeof(last_seen) - 1);

  while (running && task->is_running == 1) {
    // Check if there's new content in the task's output buffer
    pthread_mutex_lock(&task->output_mutex);

    // Check if output has changed
    if (strcmp(last_seen, task->output) != 0) {
      // Find the new content by comparing with what we've seen
      size_t match_len = 0;
      while (match_len < strlen(last_seen) &&
             match_len < strlen(task->output) &&
             last_seen[match_len] == task->output[match_len]) {
        match_len++;
      }

      // Print only the new content
      if (strlen(task->output) > match_len) {
        printf("%s", task->output + match_len);
        fflush(stdout);
      }

      // Update last seen content
      strncpy(last_seen, task->output, sizeof(last_seen) - 1);
    }

    pthread_mutex_unlock(&task->output_mutex);

    // Check task status
    if (kill(task->pid, 0) != 0) {
      // Process no longer exists
      task->is_running = 0;
      break;
    }

    // Check for detach signal
    if (attach_interrupted) {
      running = 0;
      attach_interrupted = 0;
      printf("\nDetached from task %d (process continuing in background)\n",
             task_id);
    }

    usleep(100000); // Sleep for 100ms to reduce CPU usage
  }

  // Restore default signal handler
  sa.sa_handler = SIG_DFL;
  sigaction(SIGINT, &sa, NULL);

  set_terminal_canonical_mode();

  if (task->is_running == 0) {
    printf("\nTask %d has completed\n", task_id);
  }
}

void schedule_command(const char *command, time_t scheduled_time) {
  if (num_scheduled_tasks >= MAX_SCHEDULED_TASKS) {
    printf("Cannot schedule more tasks. Maximum limit reached.\n");
    return;
  }

  ScheduledTask *task = &scheduled_tasks[num_scheduled_tasks++];
  strncpy(task->command, command, MAX_COMMAND_LEN);
  task->scheduled_time = scheduled_time;
  printf("Task scheduled: %s\n", command);
}

void check_scheduled_tasks(char *container_root) {
  time_t current_time = time(NULL);

  for (int i = 0; i < num_scheduled_tasks; i++) {
    ScheduledTask *task = &scheduled_tasks[i];

    if (task->scheduled_time <= current_time) {
      printf("Executing scheduled task: %s\n", task->command);
      execute_command(task->command, container_root);

      // Remove the task from the list
      memmove(&scheduled_tasks[i], &scheduled_tasks[i + 1],
              (num_scheduled_tasks - i - 1) * sizeof(ScheduledTask));
      num_scheduled_tasks--;
      i--; // Adjust the index after removal
    }
  }
}

void list_scheduled_tasks() {
  printf("Scheduled tasks:\n");
  for (int i = 0; i < num_scheduled_tasks; i++) {
    ScheduledTask *task = &scheduled_tasks[i];
    printf("%d. %s\n", i + 1, task->command);
  }
}

time_t parse_time(const char *time_str) {
  struct tm time_struct;
  char *format;

  format = "%H:%M";
  if (strptime(time_str, format, &time_struct) != NULL) {
    return mktime(&time_struct);
  }

  format = "%Y-%m-%d %H:%M";
  if (strptime(time_str, format, &time_struct) != NULL) {
    return mktime(&time_struct);
  }

  // If none of the formats match, return -1
  return -1;
}
