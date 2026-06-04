#include <json-c/json.h>
#include "osxiec_script/osxiec_script.h"
#include "plugin_manager/plugin_manager.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <curl/curl.h>
#include <dirent.h>
#include <errno.h>
#include <libgen.h>
#include <mach-o/dyld.h>
#include <mach/mach.h>
#include <pthread.h>
#include <pwd.h>
#include <readline/readline.h>
#include <regex.h>
#include <sandbox.h>
#include <signal.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>

#define OSXIEC_ARCHITECTURE "arm64"
#define MAX_COMMAND_LEN 1024
#define MAX_PATH_LEN 256
#define MAX_FILE_SIZE 1024 * 1024 * 1024 // 1 GB
#define MAX_FILES 100000
#define PORT 3000
#define MAX_CLIENTS 15
#define DEBUG_NONE 0
#define DEBUG_STEP 1
#define DEBUG_BREAK 2
#define CHUNK_SIZE 8192 // 8 KB chunks
#define SHARED_FOLDER_PATH "/Volumes/SharedContainer"
#define CPU_USAGE_THRESHOLD 80.0    // 80% CPU usage
#define MEMORY_USAGE_THRESHOLD 80.0 // 80% of soft limit
#define MAX_CPU_PRIORITY 39         // Maximum nice value
#define MIN_CPU_PRIORITY -20        // Minimum nice value
#define MAX_MEMORY_LIMIT 2147483648 // 2 GB max memory limit
#define MAX_HISTORY_LEN 100
#define MAX_LINE_LEN 1024
#define VERSION "v1.0"
#define MAX_BACKGROUND_THREADS 32
#define EVENT_CONTAINER_STOP 0
#define EVENT_CONTAINER_START 1
#define MAX_SCHEDULED_TASKS 32
#define MAX_DEPS 256
#define MAX_SECRETS 64
#define MAX_VAR_LEN 1024

int port = PORT;

typedef struct {
  char name[MAX_PATH_LEN];
  size_t size;
  char *data;
} File;

typedef struct {
  char source[MAX_PATH_LEN];
  char target[MAX_PATH_LEN];
} Mount;

typedef struct {
  char name[MAX_PATH_LEN];
  long memory_soft_limit;
  long memory_hard_limit;
  int cpu_priority;
  char network_mode[20];
  uid_t container_uid;
  gid_t container_gid;
  char network_name[MAX_PATH_LEN];
  int vlan_id;
  char start_config[MAX_PATH_LEN];
  char dependencies[MAX_DEPS][MAX_PATH_LEN];
  int num_dependencies;
} ContainerConfig;

typedef struct {
  char name[MAX_PATH_LEN];
  int vlan_id;
  int num_containers;
  char container_names[MAX_CLIENTS][MAX_PATH_LEN];
  char container_ips[MAX_CLIENTS][16];
} ContainerNetwork;

int debug_mode = DEBUG_NONE;
char *breakpoint = NULL;

typedef struct {
  char name[MAX_VAR_LEN];
  char *encrypted_value;
  size_t length;
} SecretVariable;

typedef struct {
  char current_directory[MAX_PATH_LEN];
  char last_executed_command[MAX_COMMAND_LEN];
  int num_processes;
  long memory_usage;
  char network_status[50];
  char **environment_variables;
  int num_env_vars;
  SecretVariable secrets[MAX_SECRETS];
  int num_secrets;
} ContainerState;

ContainerState container_state = {0};

typedef struct {
  char commands[MAX_HISTORY_LEN][MAX_COMMAND_LEN];
  int count;
  int current;
} CommandHistory;

CommandHistory history = {.count = 0, .current = 0};

typedef struct {
  char name[MAX_PATH_LEN];
  char data[4096];
  char audit_data[2048];
  char outdated_data[1024];
} BrewInfo;

int read_files(const char *dir_path, File *files, uid_t uid, gid_t gid) {
  DIR *dir;
  struct dirent *entry;
  char file_path[MAX_PATH_LEN];
  int num_files = 0;
  struct stat st;

  dir = opendir(dir_path);
  if (dir == NULL) {
    perror("Error opening directory");
    return -1;
  }

  while ((entry = readdir(dir)) != NULL) {
    snprintf(file_path, sizeof(file_path), "%s/%s", dir_path, entry->d_name);

    if (stat(file_path, &st) == 0) {
      if (S_ISDIR(st.st_mode)) {
        // Skip "." and ".."
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
          continue;
        // Recursively read subdirectories
        int sub_num_files = read_files(file_path, &files[num_files], uid, gid);
        if (sub_num_files < 0) {
          closedir(dir);
          return -1;
        }
        num_files += sub_num_files;
      } else if (S_ISREG(st.st_mode)) {
        if (st.st_size > MAX_FILE_SIZE) {
          fprintf(stderr, "File %s is too large (max %d bytes)\n",
                  entry->d_name, MAX_FILE_SIZE);
          continue;
        }

        strncpy(files[num_files].name, file_path, MAX_PATH_LEN - 1);
        files[num_files].name[MAX_PATH_LEN - 1] = '\0';
        files[num_files].size = st.st_size;

        files[num_files].data = malloc(st.st_size);
        if (files[num_files].data == NULL) {
          perror("Error allocating memory for file data");
          closedir(dir);
          return -1;
        }

        FILE *file = fopen(file_path, "rb");
        if (file == NULL) {
          perror("Error opening file");
          free(files[num_files].data);
          closedir(dir);
          return -1;
        }

        if (fread(files[num_files].data, 1, st.st_size, file) != st.st_size) {
          perror("Error reading file");
          fclose(file);
          free(files[num_files].data);
          closedir(dir);
          return -1;
        }

        fclose(file);

        // Set appropriate permissions
        if (chmod(file_path, 0755) != 0) {
          perror("Error setting file permissions");
          free(files[num_files].data);
          closedir(dir);
          return -1;
        }

        // Change ownership of the file
        if (chown(file_path, uid, gid) != 0) {
          perror("Error changing file ownership");
          free(files[num_files].data);
          closedir(dir);
          return -1;
        }

        num_files++;
      }
    }
  }

  closedir(dir);
  return num_files;
}

extern char **environ;

void update_container_state() {
  // Update current directory
  getcwd(container_state.current_directory, MAX_PATH_LEN);

  // Update number of processes
  container_state.num_processes = 1;

  // Update memory usage
  FILE *file = fopen("/proc/self/status", "r");
  if (file) {
    char line[128];
    while (fgets(line, sizeof(line), file)) {
      if (strncmp(line, "VmRSS:", 6) == 0) {
        sscanf(line + 6, "%ld", &container_state.memory_usage);
        break;
      }
    }
    fclose(file);
  }

  strcpy(container_state.network_status, "Connected");

  // Update environment variables
  for (int i = 0; environ[i] != NULL; i++) {
    if (i >= container_state.num_env_vars) {
      container_state.environment_variables = realloc(
          container_state.environment_variables, (i + 1) * sizeof(char *));
      container_state.environment_variables[i] = strdup(environ[i]);
      container_state.num_env_vars++;
    } else if (strcmp(container_state.environment_variables[i], environ[i]) !=
               0) {
      free(container_state.environment_variables[i]);
      container_state.environment_variables[i] = strdup(environ[i]);
    }
  }
}

void print_container_state() {
  update_container_state();

  printf("Container State:\n");
  printf("  Current Directory: %s\n", container_state.current_directory);
  printf("  Last Executed Command: %s\n",
         container_state.last_executed_command);
  printf("  Number of Processes: %d\n", container_state.num_processes);
  printf("  Network Status: %s\n", container_state.network_status);
  printf("  Environment Variables:\n");
  for (int i = 0; i < container_state.num_env_vars; i++) {
    printf("    %s\n", container_state.environment_variables[i]);
  }
}

void handle_debug_command(char *command) {
  if (strcmp(command, "continue") == 0 || strcmp(command, "c") == 0) {
    debug_mode = DEBUG_NONE;
  } else if (strcmp(command, "step") == 0 || strcmp(command, "s") == 0) {
    debug_mode = DEBUG_STEP;
  } else if (strncmp(command, "break ", 6) == 0) {
    if (breakpoint)
      free(breakpoint);
    breakpoint = strdup(command + 6);
    debug_mode = DEBUG_BREAK;
  } else if (strcmp(command, "print") == 0 || strcmp(command, "p") == 0) {
    print_container_state();
  } else if (strncmp(command, "print ", 6) == 0 ||
             strncmp(command, "p ", 2) == 0) {
    char *var_name = command + (command[1] == ' ' ? 2 : 6);
    char *var_value = getenv(var_name);
    if (var_value) {
      printf("%s = %s\n", var_name, var_value);
    } else {
      printf("Variable %s not found\n", var_name);
    }
  } else if (strcmp(command, "help") == 0 || strcmp(command, "h") == 0) {
    printf("Debug commands:\n");
    printf("  continue (c) - Continue execution\n");
    printf("  step (s) - Step to next command\n");
    printf("  break <command> - Set breakpoint at command\n");
    printf("  print (p) - Print container state\n");
    printf("  print <var> (p <var>) - Print value of environment variable\n");
    printf("  help (h) - Show this help message\n");
  } else {
    printf("Unknown debug command. Type 'help' for a list of commands.\n");
  }
}

int is_subpath(const char *path, const char *base) {
  char resolved_path[PATH_MAX];
  char resolved_base[PATH_MAX];

  if (realpath(path, resolved_path) == NULL ||
      realpath(base, resolved_base) == NULL) {
    return 0;
  }

  return strncmp(resolved_path, resolved_base, strlen(resolved_base)) == 0;
}

void execute_command(const char *command, const char *container_root) {
  if (command == NULL || strlen(command) == 0) {
    fprintf(stderr, "Error: Empty command\n");
    return;
  }

  if (debug_mode == DEBUG_STEP || (debug_mode == DEBUG_BREAK && breakpoint &&
                                   strstr(command, breakpoint))) {
    printf("Debugger: Paused at command: %s\n", command);
    char *debug_cmd;
    while ((debug_cmd = readline("debug> ")) != NULL) {
      handle_debug_command(debug_cmd);
      free(debug_cmd);
      if (debug_mode == DEBUG_NONE)
        break;
    }
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
    if (waitpid(pid, &status, 0) != -1) {
      if (WIFEXITED(status)) {
        int exit_status = WEXITSTATUS(status);
        if (exit_status != 0) {
          printf("Child process exited with status %d\n", exit_status);
        }
      } else if (WIFSIGNALED(status)) {
        printf("Child process terminated by signal %d\n", WTERMSIG(status));
      }
    } else {
      perror("Error waiting for child process");
    }
  } else {
    fprintf(stderr, "posix_spawnp failed: %s\n", strerror(ret));
  }

  posix_spawn_file_actions_destroy(&actions);
  posix_spawnattr_destroy(&attr);
  free(command_copy);
}

void execute_start_config(const char *config_file, const char *container_root) {
  FILE *file = fopen(config_file, "r");
  if (file == NULL) {
    perror("Error opening start configuration file");
    return;
  }

  char line[MAX_COMMAND_LEN];
  while (fgets(line, sizeof(line), file)) {
    // Remove newline character if present
    line[strcspn(line, "\n")] = 0;

    // Skip empty lines and comments
    if (line[0] == '\0' || line[0] == '#') {
      continue;
    }

    printf("Executing start command: %s\n", line);
    execute_command(line, container_root);
  }

  fclose(file);
}

int is_base64(const char *str) {
  regex_t regex;
  int reti = regcomp(&regex, "^[A-Za-z0-9+/]+={0,2}$", REG_EXTENDED);
  if (reti) {
    return 0;
  }
  reti = regexec(&regex, str, 0, NULL, 0);
  regfree(&regex);
  return (reti == 0);
}

void security_scan(const char *bin_file) {
  FILE *file = fopen(bin_file, "rb");
  if (file == NULL) {
    perror("Error opening binary file for security scan");
    return;
  }

  ContainerConfig config;
  if (fread(&config, sizeof(ContainerConfig), 1, file) != 1) {
    perror("Error reading container config during security scan");
    fclose(file);
    return;
  }

  printf("Performing security scan on %s\n", bin_file);

  if (strcmp(config.network_mode, "host") == 0) {
    printf("HIGH RISK: Container is using host network mode. This can be a "
           "significant security risk.\n");
    printf("The host network error will not be revelenant if you use the vlan "
           "network.\n");
  }

  // Check resource limits
  if (config.memory_hard_limit == 0) {
    printf("MEDIUM RISK: No hard memory limit set. This could lead to resource "
           "exhaustion.\n");
  }

  if (config.cpu_priority == 0) {
    printf("LOW RISK: No CPU priority set. This could lead to resource "
           "contention.\n");
  }

  // Check for excessive resource allocation
  if (config.memory_hard_limit > 8589934592) { // 8GB
    printf("MEDIUM RISK: Very high memory limit set (%lu bytes). Consider if "
           "necessary.\n",
           config.memory_hard_limit);
  }

  int num_files;
  fread(&num_files, sizeof(int), 1, file);

  regex_t regex;
  regcomp(&regex, "^[a-zA-Z0-9._/-]+$", REG_EXTENDED);

  // Track file statistics
  int executable_count = 0;
  int config_count = 0;
  size_t total_size = 0;

  for (int i = 0; i < num_files; i++) {
    char file_name[MAX_PATH_LEN];
    size_t file_size;

    fread(file_name, sizeof(char), MAX_PATH_LEN, file);
    fread(&file_size, sizeof(size_t), 1, file);

    total_size += file_size;

    // Check for potentially dangerous file names
    if (strstr(file_name, "..") != NULL) {
      printf("HIGH RISK: File '%s' contains potentially dangerous '..' in its "
             "path.\n",
             file_name);
    }

    if (regexec(&regex, file_name, 0, NULL, 0) != 0) {
      printf("MEDIUM RISK: File '%s' has a potentially unsafe name.\n",
             file_name);
    }

    // Check for overly permissive file permissions
    if (strstr(file_name, ".sh") != NULL || strstr(file_name, ".py") ||
        strstr(file_name, ".lua") != NULL || strstr(file_name, ".pl") != NULL) {
      printf("LOW RISK: Script file detected: '%s'. Ensure it has appropriate "
             "permissions.\n",
             file_name);
      executable_count++;
    }

    // Check for configuration files
    if (strstr(file_name, ".conf") != NULL ||
        strstr(file_name, ".cfg") != NULL ||
        strstr(file_name, ".ini") != NULL ||
        strstr(file_name, ".yaml") != NULL ||
        strstr(file_name, ".yml") != NULL ||
        strstr(file_name, ".json") != NULL) {
      config_count++;
    }

    // Check for sensitive files
    if (strstr(file_name, "id_rsa") != NULL ||
        strstr(file_name, ".pem") != NULL ||
        strstr(file_name, ".key") != NULL ||
        strstr(file_name, ".crt") != NULL) {
      printf("HIGH RISK: Potential private key/certificate file detected: "
             "'%s'. Ensure "
             "it's properly secured.\n",
             file_name);
    }

    if (strstr(file_name, "password") != NULL ||
        strstr(file_name, "secret") != NULL ||
        strstr(file_name, "passwd") != NULL ||
        strstr(file_name, "shadow") != NULL) {
      printf("HIGH RISK: Potential sensitive file detected: '%s'. Ensure it's "
             "properly secured.\n",
             file_name);
    }

    // Check for system files that shouldn't be in containers
    if (strstr(file_name, "/etc/passwd") != NULL ||
        strstr(file_name, "/etc/shadow") != NULL ||
        strstr(file_name, "/proc/") != NULL ||
        strstr(file_name, "/sys/") != NULL) {
      printf("HIGH RISK: System file '%s' detected. This may indicate host "
             "access.\n",
             file_name);
    }

    // Check for large files
    if (file_size > 104857600) { // 100MB
      printf(
          "MEDIUM RISK: Large file '%s' (%zu bytes) may impact performance.\n",
          file_name, file_size);
    }

    // Scan file contents
    char *buffer = malloc(file_size + 1);
    if (buffer == NULL) {
      perror("Failed to allocate memory for file content");
      continue;
    }

    fread(buffer, 1, file_size, file);
    buffer[file_size] = '\0';

    // Check for insecure environment variables
    if (strstr(buffer, "ENV_VAR_WITH_SENSITIVE_INFO") != NULL) {
      printf(
          "MEDIUM RISK: Insecure environment variable detected in file '%s'.\n",
          file_name);
    }

    // Check for insecure capabilities
    if (strstr(buffer, "CAP_SYS_ADMIN") != NULL) {
      printf("HIGH RISK: Insecure capability detected in file '%s'.\n",
             file_name);
    }

    // Check for insecure file permissions
    if (strstr(buffer, "chmod 777") != NULL ||
        strstr(buffer, "chmod 666") != NULL) {
      printf("HIGH RISK: Insecure file permissions detected in file '%s'.\n",
             file_name);
    }

    // Check for hardcoded credentials
    regex_t pwd_regex;
    if (regcomp(&pwd_regex,
                "(password|api_key|secret|token)\\s*[=:]\\s*['\"][^'\"]+['\"]",
                REG_EXTENDED | REG_ICASE) == 0) {
      if (regexec(&pwd_regex, buffer, 0, NULL, 0) == 0) {
        printf("HIGH RISK: Potential hardcoded credentials detected in file "
               "'%s'.\n",
               file_name);
      }
      regfree(&pwd_regex);
    }

    // Check for potential SQL injection vulnerabilities
    if (strstr(buffer, "SELECT") != NULL && strstr(buffer, "WHERE") != NULL &&
        strstr(buffer, "+") != NULL) {
      printf("HIGH RISK: Potential SQL injection vulnerability detected in "
             "file '%s'.\n",
             file_name);
    }

    // Check for suspicious network calls
    if (strstr(buffer, "curl") != NULL || strstr(buffer, "wget") != NULL ||
        strstr(buffer, "nc ") != NULL || strstr(buffer, "netcat") != NULL) {
      printf("MEDIUM RISK: Network tool usage detected in file '%s'. "
             "Verify legitimacy.\n",
             file_name);
    }

    // Check for package managers (potential supply chain risks)
    if (strstr(buffer, "pip install") != NULL ||
        strstr(buffer, "npm install") != NULL ||
        strstr(buffer, "apt-get install") != NULL ||
        strstr(buffer, "brew install") != NULL) {
      printf("MEDIUM RISK: Package installation detected in file '%s'. "
             "Verify package sources.\n",
             file_name);
    }

    // Check for base64 encoded strings (potential hidden data)
    char *token = strtok(buffer, " \t\n");
    while (token != NULL) {
      if (strlen(token) > 20 && is_base64(token)) {
        printf("LOW RISK: Potential base64 encoded data detected in file '%s'. "
               "Verify if it contains sensitive information.\n",
               file_name);
        break;
      }
      token = strtok(NULL, " \t\n");
    }

    free(buffer);
  }

  regfree(&regex);

  // Summary statistics
  printf("\n--- Scan Summary ---\n");
  printf("Total files scanned: %d\n", num_files);
  printf("Executable/script files: %d\n", executable_count);
  printf("Configuration files: %d\n", config_count);
  printf("Total container size: %zu bytes (%.2f MB)\n", total_size,
         (double)total_size / 1048576);

  printf("Security scan completed.\n");
  fclose(file);
}

void read_config_file(const char *filename, ContainerConfig *config) {
  FILE *file = fopen(filename, "r");
  if (file == NULL) {
    perror("Error opening config file");
    exit(EXIT_FAILURE);
  }

  char line[MAX_LINE_LEN];
  while (fgets(line, sizeof(line), file)) {
    char key[64], value[MAX_LINE_LEN];
    if (sscanf(line, "%63[^=]=%[^\n]", key, value) == 2) {
      if (strcmp(key, "name") == 0) {
        strncpy(config->name, value, sizeof(config->name) - 1);
        config->name[sizeof(config->name) - 1] = '\0';
      } else if (strcmp(key, "memory_soft_limit") == 0) {
        config->memory_soft_limit = strtoul(value, NULL, 10);
      } else if (strcmp(key, "memory_hard_limit") == 0) {
        config->memory_hard_limit = strtoul(value, NULL, 10);
      } else if (strcmp(key, "cpu_priority") == 0) {
        config->cpu_priority = atoi(value);
      } else if (strcmp(key, "network_mode") == 0) {
        strncpy(config->network_mode, value, sizeof(config->network_mode) - 1);
        config->network_mode[sizeof(config->network_mode) - 1] = '\0';
      } else if (strcmp(key, "container_uid") == 0) {
        config->container_uid = atoi(value);
      } else if (strcmp(key, "container_gid") == 0) {
        config->container_gid = atoi(value);
      } else if (strcmp(key, "dependencies") == 0) {
        // Parse comma-separated dependencies
        config->num_dependencies = 0;
        char *token = strtok(value, ",");
        while (token != NULL && config->num_dependencies < MAX_DEPS) {
          // Remove leading/trailing whitespace
          while (*token == ' ')
            token++;
          char *end = token + strlen(token) - 1;
          while (end > token && (*end == ' ' || *end == '\n' || *end == '\r'))
            end--;
          *(end + 1) = '\0';

          if (strlen(token) > 0) {
            strncpy(config->dependencies[config->num_dependencies], token,
                    MAX_PATH_LEN - 1);
            config->dependencies[config->num_dependencies][MAX_PATH_LEN - 1] =
                '\0';
            config->num_dependencies++;
          }
          token = strtok(NULL, ",");
        }
      }
    }
  }
  fclose(file);
}

const char *get_homebrew_prefix() {
  if (strcmp(OSXIEC_ARCHITECTURE, "arm64") == 0) {
    return "/opt/homebrew";
  } else {
    return "/usr/local";
  }
}

int get_brew_info(const char *package_name, BrewInfo *info) {
  const char *sudo_user = getenv("SUDO_USER");
  const char *brew_paths[] = {"/opt/homebrew/bin/brew", "/usr/local/bin/brew",
                              "brew"};
  char command[MAX_PATH_LEN];
  FILE *fp = NULL;
  char *brew_path = NULL;

  // First find which brew path works
  for (int i = 0; i < 3; i++) {
    snprintf(command, sizeof(command), "sudo -H -u %s %s --version 2>&1",
             sudo_user, brew_paths[i]);

    fp = popen(command, "r");
    if (fp != NULL) {
      int first_char = fgetc(fp);
      pclose(fp);
      if (first_char != EOF) {
        brew_path = (char *)brew_paths[i];
        break;
      }
    }
  }

  if (brew_path == NULL) {
    fprintf(stderr, "  Failed to find working brew executable.\n");
    return -1;
  }

  printf("  Using brew at: %s\n", brew_path);

  // Initialize the info structure we run sudo with paramater -H -u to avoid the
  // brew warning that we can't run it in sudo. Basicly for a short time we
  // switch to a home user
  strncpy(info->name, package_name, MAX_PATH_LEN - 1);
  info->name[MAX_PATH_LEN - 1] = '\0';
  info->data[0] = '\0';
  info->audit_data[0] = '\0';
  info->outdated_data[0] = '\0';

  // 1. Get brew info
  snprintf(command, sizeof(command), "sudo -H -u %s %s info %s 2>&1", sudo_user,
           brew_path, package_name);

  printf("  Getting brew info: %s\n", command);
  fp = popen(command, "r");
  if (fp != NULL) {
    size_t data_len = 0;
    char buffer[1024];
    while (fgets(buffer, sizeof(buffer), fp) != NULL &&
           data_len < sizeof(info->data) - 1) {
      size_t len = strlen(buffer);
      if (data_len + len < sizeof(info->data) - 1) {
        strcat(info->data + data_len, buffer);
        data_len += len;
      }
    }
    pclose(fp);
    printf("  Got brew info data (%zu bytes)\n", strlen(info->data));
  }

  // 2. Run brew audit for security issues
  snprintf(command, sizeof(command), "sudo -H -u %s %s audit --formula %s 2>&1",
           sudo_user, brew_path, package_name);

  printf("  Running security audit: %s\n", command);
  fp = popen(command, "r");
  if (fp != NULL) {
    size_t audit_len = 0;
    char buffer[1024];
    while (fgets(buffer, sizeof(buffer), fp) != NULL &&
           audit_len < sizeof(info->audit_data) - 1) {
      size_t len = strlen(buffer);
      if (audit_len + len < sizeof(info->audit_data) - 1) {
        strcat(info->audit_data + audit_len, buffer);
        audit_len += len;
      }
    }
    pclose(fp);

    if (strlen(info->audit_data) > 0) {
      printf("  Security audit results (%zu bytes):\n",
             strlen(info->audit_data));
      printf("  %s\n", info->audit_data);
    } else {
      printf("  No security issues found in audit\n");
      strcpy(info->audit_data, "No security issues detected");
    }
  }

  // 3. Check if package is outdated (potential security risk)
  snprintf(command, sizeof(command), "sudo -H -u %s %s outdated %s 2>&1",
           sudo_user, brew_path, package_name);

  printf("  Checking for updates: %s\n", command);
  fp = popen(command, "r");
  if (fp != NULL) {
    size_t outdated_len = 0;
    char buffer[1024];
    while (fgets(buffer, sizeof(buffer), fp) != NULL &&
           outdated_len < sizeof(info->outdated_data) - 1) {
      size_t len = strlen(buffer);
      if (outdated_len + len < sizeof(info->outdated_data) - 1) {
        strcat(info->outdated_data + outdated_len, buffer);
        outdated_len += len;
      }
    }
    pclose(fp);

    if (strlen(info->outdated_data) > 0) {
      printf("  Package is outdated: %s\n", info->outdated_data);
    } else {
      printf("  Package is up to date\n");
      strcpy(info->outdated_data, "Package is up to date");
    }
  }

  return 0;
}

void analyze_security_findings(const BrewInfo *info) {
  printf("\n=== Security Analysis for %s ===\n", info->name);

  // Check audit results for common security keywords
  const char *security_keywords[] = {"vulnerability", "CVE-",    "security",
                                     "exploit",       "unsafe",  "deprecated",
                                     "insecure",      "warning", "error"};

  int security_issues_found = 0;
  for (int i = 0; i < 8; i++) {
    if (strstr(info->audit_data, security_keywords[i]) != NULL) {
      security_issues_found = 1;
      break;
    }
  }

  if (security_issues_found) {
    printf("  ⚠️  SECURITY ISSUES DETECTED:\n");
    printf("  %s\n", info->audit_data);
  } else {
    printf("  ✅ No security issues detected in audit\n");
  }

  // Check if outdated (security risk)
  if (strstr(info->outdated_data, info->name) != NULL) {
    printf("  ⚠️  OUTDATED PACKAGE (potential security risk):\n");
    printf("  %s\n", info->outdated_data);
  } else {
    printf("  ✅ Package is up to date\n");
  }

  printf("===================================\n\n");
}

int parse_brew_dependencies(const char *brew_info_data,
                            char deps[][MAX_PATH_LEN], int max_deps) {
  int dep_count = 0;

  printf("  Parsing dependencies from brew info data...\n");
  printf("  Looking for dependencies in: %.200s...\n", brew_info_data);

  // Look for different dependency patterns that brew info might show
  const char *patterns[] = {"==> Dependencies",
                            "Required:", "Build:", "Optional:", "Recommended:"};

  for (int p = 0; p < 5; p++) {
    const char *deps_section = strstr(brew_info_data, patterns[p]);
    if (deps_section != NULL) {
      printf("  Found dependency section: %s\n", patterns[p]);

      // Skip to the actual dependency list
      const char *start = deps_section + strlen(patterns[p]);

      // Find the end of the line
      const char *line_end = strchr(start, '\n');
      if (line_end == NULL) {
        continue;
      }

      // Extract the dependency line
      size_t line_len = line_end - start;
      if (line_len > 1000)
        line_len = 1000; // Safety limit

      char deps_line[1024];
      strncpy(deps_line, start, line_len);
      deps_line[line_len] = '\0';

      printf("  Dependency line: '%s'\n", deps_line);

      // Parse comma and space separated depedencies
      char *token = strtok(deps_line, ", \t");
      while (token != NULL && dep_count < max_deps) {
        // Clean up the token
        while (*token == ' ' || *token == '\t')
          token++;
        char *end = token + strlen(token) - 1;
        while (end > token &&
               (*end == ' ' || *end == '\t' || *end == '\n' || *end == '\r'))
          end--;
        *(end + 1) = '\0';

        // Skip empty tokens and common non-dependency words
        if (strlen(token) > 0 && strcmp(token, "None") != 0 &&
            strcmp(token, "none") != 0 && strcmp(token, "Required:") != 0 &&
            strcmp(token, "Build:") != 0 && strcmp(token, "Optional:") != 0) {

          strncpy(deps[dep_count], token, MAX_PATH_LEN - 1);
          deps[dep_count][MAX_PATH_LEN - 1] = '\0';
          printf("  Found dependency: '%s'\n", deps[dep_count]);
          dep_count++;
        }
        token = strtok(NULL, ", \t");
      }

      // If we found dependencies in this section, we can stop looking
      if (dep_count > 0) {
        break;
      }
    }
  }

  printf("  Total dependencies found: %d\n", dep_count);
  return dep_count;
}

int file_exists(const char *path) {
  struct stat st;
  return stat(path, &st) == 0;
}

int copy_single_file(const char *src_path, const char *dest_path, File *files,
                     int *file_count, int max_files) {
  if (*file_count >= max_files) {
    printf("  ERROR: Max files limit reached (%d)\n", max_files);
    return 0;
  }

  printf("  Attempting to copy file: %s -> %s\n", src_path, dest_path);

  FILE *src_file = fopen(src_path, "rb");
  if (src_file == NULL) {
    printf("  ERROR: Cannot open source file: %s\n", src_path);
    return 0;
  }

  // Get file size
  fseek(src_file, 0, SEEK_END);
  size_t file_size = ftell(src_file);
  fseek(src_file, 0, SEEK_SET);

  printf("  File size: %zu bytes\n", file_size);

  // Allocate memory and read file
  char *file_data = malloc(file_size);
  if (file_data == NULL) {
    printf("  ERROR: Cannot allocate memory for file data (%zu bytes)\n",
           file_size);
    fclose(src_file);
    return 0;
  }

  size_t bytes_read = fread(file_data, 1, file_size, src_file);
  fclose(src_file);

  if (bytes_read != file_size) {
    printf("  ERROR: Only read %zu of %zu bytes\n", bytes_read, file_size);
    free(file_data);
    return 0;
  }

  // Add to files array
  strncpy(files[*file_count].name, dest_path, MAX_PATH_LEN - 1);
  files[*file_count].name[MAX_PATH_LEN - 1] = '\0';
  files[*file_count].size = file_size;
  files[*file_count].data = file_data;
  (*file_count)++;

  printf("  SUCCESS: Added file to container (index %d)\n", *file_count - 1);

  return 1;
}

int copy_path(const char *src_path, const char *dest_path, File *files,
              int *file_count, int max_files) {
  printf("  Checking path: %s\n", src_path);

  struct stat st;
  if (stat(src_path, &st) != 0) {
    printf("  ERROR: Path does not exist: %s\n", src_path);
    return 0;
  }

  if (S_ISREG(st.st_mode)) {
    // It's a single file, copy it directly
    printf("  Found regular file\n");
    return copy_single_file(src_path, dest_path, files, file_count, max_files);
  } else if (S_ISDIR(st.st_mode)) {
    // It's a directory, copy recursively
    printf("  Found directory, copying recursively\n");
    DIR *dir = opendir(src_path);
    if (dir == NULL) {
      printf("  ERROR: Cannot open directory: %s\n", src_path);
      return 0;
    }

    int files_copied = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL && *file_count < max_files) {
      if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
        continue;
      }

      char full_src_path[MAX_PATH_LEN];
      char full_dest_path[MAX_PATH_LEN];
      snprintf(full_src_path, sizeof(full_src_path), "%s/%s", src_path,
               entry->d_name);
      snprintf(full_dest_path, sizeof(full_dest_path), "%s/%s", dest_path,
               entry->d_name);

      if (copy_path(full_src_path, full_dest_path, files, file_count,
                    max_files)) {
        files_copied++;
      }
    }

    closedir(dir);
    printf("  Copied %d files from directory: %s\n", files_copied, src_path);
    return files_copied > 0 ? 1 : 0;
  }

  printf("  WARNING: Path is neither file nor directory: %s\n", src_path);
  return 0;
}

int process_dependency(const char *dep_name, const char *homebrew_prefix,
                       File *files, int *file_count, int max_files) {
  printf("Processing dependency: %s\n", dep_name);

  // Common paths where brew installs files
  const char *subdirs[] = {"lib",   "bin", "opt",    "include",
                           "share", "etc", "Cellar", "var"};
  int num_subdirs = sizeof(subdirs) / sizeof(subdirs[0]);

  for (int i = 0; i < num_subdirs; i++) {
    char src_path[MAX_PATH_LEN];
    char dest_path[MAX_PATH_LEN];

    // Check for dependency-specific directory first
    snprintf(src_path, sizeof(src_path), "%s/%s/%s", homebrew_prefix,
             subdirs[i], dep_name);
    // Preserve the original homebrew structure in the container
    snprintf(dest_path, sizeof(dest_path), "%s/%s/%s", homebrew_prefix,
             subdirs[i], dep_name);

    if (file_exists(src_path)) {
      copy_path(src_path, dest_path, files, file_count, max_files);
    }

    // Check for files with dependency name pattern
    if (strcmp(subdirs[i], "lib") == 0) {
      // Look for lib{dep_name}.dylib pattern
      char lib_pattern[MAX_PATH_LEN];
      snprintf(lib_pattern, sizeof(lib_pattern), "%s/lib/lib%s.dylib",
               homebrew_prefix, dep_name);
      snprintf(dest_path, sizeof(dest_path), "%s/lib/lib%s.dylib",
               homebrew_prefix, dep_name);

      if (file_exists(lib_pattern)) {
        copy_single_file(lib_pattern, dest_path, files, file_count, max_files);
      }
    }

    // Check for binary executables in bin directory
    if (strcmp(subdirs[i], "bin") == 0) {
      char bin_pattern[MAX_PATH_LEN];
      snprintf(bin_pattern, sizeof(bin_pattern), "%s/bin/%s", homebrew_prefix,
               dep_name);
      snprintf(dest_path, sizeof(dest_path), "%s/bin/%s", homebrew_prefix,
               dep_name);

      if (file_exists(bin_pattern)) {
        copy_single_file(bin_pattern, dest_path, files, file_count, max_files);
      }
    }
  }

  // Also check for the dependency's own opt directory (like
  // /opt/homebrew/opt/neofetch)
  char opt_path[MAX_PATH_LEN];
  char opt_dest_path[MAX_PATH_LEN];
  snprintf(opt_path, sizeof(opt_path), "%s/opt/%s", homebrew_prefix, dep_name);
  snprintf(opt_dest_path, sizeof(opt_dest_path), "%s/opt/%s", homebrew_prefix,
           dep_name);

  if (file_exists(opt_path)) {
    printf("  Found opt directory for %s\n", dep_name);
    copy_path(opt_path, opt_dest_path, files, file_count, max_files);
  }

  return 0;
}

int process_dependencies_recursive(const char *dep_name,
                                   const char *homebrew_prefix, File *files,
                                   int *file_count, int max_files,
                                   char processed[][MAX_PATH_LEN],
                                   int *processed_count) {

  // Check if already processed
  for (int i = 0; i < *processed_count; i++) {
    if (strcmp(processed[i], dep_name) == 0) {
      return 0; // Already processed
    }
  }

  printf("  Analyzing dependency with security scan: %s\n", dep_name);

  // Mark as processed
  strncpy(processed[*processed_count], dep_name, MAX_PATH_LEN - 1);
  processed[*processed_count][MAX_PATH_LEN - 1] = '\0';
  (*processed_count)++;

  // Get brew info AND security scan for this dependency
  BrewInfo brew_info = {0};
  if (get_brew_info(dep_name, &brew_info) == 0) {

    // Analyze security findings
    analyze_security_findings(&brew_info);

    // Parse sub-dependencies
    char sub_deps[MAX_DEPS][MAX_PATH_LEN];
    int num_sub_deps =
        parse_brew_dependencies(brew_info.data, sub_deps, MAX_DEPS);

    if (num_sub_deps > 0) {
      printf("  Found %d sub-dependencies for %s: ", num_sub_deps, dep_name);
      for (int i = 0; i < num_sub_deps; i++) {
        printf("%s%s", sub_deps[i], (i < num_sub_deps - 1) ? ", " : "");
      }
      printf("\n");
    }

    // Process sub-dependencies first
    for (int i = 0; i < num_sub_deps; i++) {
      process_dependencies_recursive(sub_deps[i], homebrew_prefix, files,
                                     file_count, max_files, processed,
                                     processed_count);
    }
  } else {
    printf("  Warning: Could not get brew info for %s\n", dep_name);
  }

  // Process the dependency itself (copy files)
  process_dependency(dep_name, homebrew_prefix, files, file_count, max_files);

  return 0;
}

int link_system_directories(const char *container_root) {
  printf("Linking core system directories to container...\n");

  const char *core_system_dirs[] = {"/bin",       "/usr/bin",     "/usr/lib",
                                    "/usr/share", "/usr/libexec", "/usr/sbin",
                                    "/sbin"};
  int num_core_dirs = sizeof(core_system_dirs) / sizeof(core_system_dirs[0]);
  int linked_count = 0;

  // Create symbolic links for core system directories
  for (int i = 0; i < num_core_dirs; i++) {
    if (file_exists(core_system_dirs[i])) {
      printf("  Linking system directory: %s\n", core_system_dirs[i]);

      char container_path[PATH_MAX];
      snprintf(container_path, sizeof(container_path), "%s%s", container_root,
               core_system_dirs[i]);

      // Create parent directories if needed
      char *container_path_copy = strdup(container_path);
      char *parent_dir = dirname(container_path_copy);
      if (mkdir(parent_dir, 0755) != 0 && errno != EEXIST) {
        printf("  Error: Failed to create parent directory for %s: %s\n",
               container_path, strerror(errno));
        free(container_path_copy);
        continue;
      }
      free(container_path_copy);

      if (symlink(core_system_dirs[i], container_path) == 0) {
        linked_count++;
      } else {
        printf("  Error: Failed to create symlink for %s: %s\n",
               core_system_dirs[i], strerror(errno));
      }

    } else {
      printf("  Warning: System directory not found: %s\n",
             core_system_dirs[i]);
    }
  }

  printf("Linked %d core system directories\n", linked_count);
  return 0;
}

void containerize_directory(const char *dir_path, const char *output_file,
                            const char *start_config_file,
                            const char *container_config_file) {
  FILE *bin_file = fopen(output_file, "wb");
  if (bin_file == NULL) {
    perror("Error opening output file");
    exit(EXIT_FAILURE);
  }

  File *files = malloc(sizeof(File) * MAX_FILES);
  if (files == NULL) {
    perror("Error allocating memory for files");
    fclose(bin_file);
    exit(EXIT_FAILURE);
  }

  int num_files = 0; // Initialize to 0

  // Initialize default config
  ContainerConfig config = {.name = "default_container",
                            .memory_soft_limit = 384 * 1024 * 1024,
                            .memory_hard_limit = 512 * 1024 * 1024,
                            .cpu_priority = 20,
                            .network_mode = "bridge",
                            .container_uid = 1000,
                            .container_gid = 1000,
                            .start_config = "",
                            .num_dependencies = 0};

  if (container_config_file) {
    read_config_file(container_config_file, &config);
  }

  if (start_config_file) {
    strncpy(config.start_config, start_config_file, MAX_PATH_LEN - 1);
    config.start_config[MAX_PATH_LEN - 1] = '\0';
  } else {
    config.start_config[0] = '\0';
  }

  const char *homebrew_prefix = get_homebrew_prefix();
  printf("Using Homebrew prefix: %s\n", homebrew_prefix);

  // Process dependencies only if we have any and config file is not null/empty
  if (config.num_dependencies > 0 && container_config_file != NULL &&
      strlen(container_config_file) > 0) {
    printf("Processing %d dependencies...\n", config.num_dependencies);

    char processed_deps[MAX_DEPS][MAX_PATH_LEN];
    int processed_count = 0;

    for (int i = 0; i < config.num_dependencies; i++) {
      process_dependencies_recursive(config.dependencies[i], homebrew_prefix,
                                     files, &num_files, MAX_FILES,
                                     processed_deps, &processed_count);
    }

    printf("Processed %d total dependencies (including sub-dependencies)\n",
           processed_count);
    printf("Added %d dependency files to container\n", num_files);
  }

  // Read files from directory and ADD to existing files (dont overwrite
  // num_files)
  int dir_files = read_files(dir_path, files + num_files, config.container_uid,
                             config.container_gid);
  if (dir_files < 0) {
    free(files);
    fclose(bin_file);
    exit(EXIT_FAILURE);
  }
  num_files += dir_files; // Add directory files to total count

  printf("Total files in container: %d (dependencies: %d, directory: %d)\n",
         num_files, num_files - dir_files, dir_files);

  fwrite(&config, sizeof(ContainerConfig), 1, bin_file);
  fwrite(&num_files, sizeof(int), 1, bin_file);

  // Display progress bar
  int progress_bar_width = 50;
  printf("Containerizing [");
  fflush(stdout);

  for (int i = 0; i < num_files; i++) {
    fwrite(files[i].name, sizeof(char), MAX_PATH_LEN, bin_file);
    fwrite(&files[i].size, sizeof(size_t), 1, bin_file);
    fwrite(files[i].data, 1, files[i].size, bin_file);
    free(files[i].data);

    // Update progress bar
    int progress = (i + 1) * progress_bar_width / num_files;
    for (int j = 0; j < progress; j++) {
      printf("#");
      fflush(stdout);
    }
    for (int j = progress; j < progress_bar_width; j++) {
      printf(" ");
      fflush(stdout);
    }
    printf("] %d%%\r", (i + 1) * 100 / num_files);
    fflush(stdout);
  }

  printf("\n");
  free(files);
  fclose(bin_file);
  security_scan(output_file);
}

void containerize_directory_with_bin_file(const char *dir_path,
                                          const char *input_bin_file,
                                          const char *output_file,
                                          const char *start_config_file,
                                          const char *container_config_file) {
  FILE *bin_file = fopen(output_file, "wb");
  if (bin_file == NULL) {
    perror("Error opening output file");
    exit(EXIT_FAILURE);
  }

  File *files = malloc(sizeof(File) * MAX_FILES);
  if (files == NULL) {
    perror("Error allocating memory for files");
    fclose(bin_file);
    exit(EXIT_FAILURE);
  }

  int num_files = 0; // Initialize to 0

  // Initialize default config
  ContainerConfig config = {.name = "default_container",
                            .memory_soft_limit = 384 * 1024 * 1024,
                            .memory_hard_limit = 512 * 1024 * 1024,
                            .cpu_priority = 20,
                            .network_mode = "bridge",
                            .container_uid = 1000,
                            .container_gid = 1000,
                            .start_config = "",
                            .num_dependencies = 0};

  // Load config from file if provided
  if (container_config_file) {
    read_config_file(container_config_file, &config);
  }

  if (start_config_file) {
    strncpy(config.start_config, start_config_file, MAX_PATH_LEN - 1);
    config.start_config[MAX_PATH_LEN - 1] = '\0';
  } else {
    config.start_config[0] = '\0';
  }

  const char *homebrew_prefix = get_homebrew_prefix();
  printf("Using Homebrew prefix: %s\n", homebrew_prefix);

  // Process dependencies only if we have any and config file is not null/empty
  if (config.num_dependencies > 0 && container_config_file != NULL &&
      strlen(container_config_file) > 0) {
    printf("Processing %d dependencies...\n", config.num_dependencies);

    char processed_deps[MAX_DEPS][MAX_PATH_LEN];
    int processed_count = 0;

    for (int i = 0; i < config.num_dependencies; i++) {
      process_dependencies_recursive(config.dependencies[i], homebrew_prefix,
                                     files, &num_files, MAX_FILES,
                                     processed_deps, &processed_count);
    }

    printf("Processed %d total dependencies (including sub-dependencies)\n",
           processed_count);
    printf("Added %d dependency files to container\n", num_files);
  }

  // Read files from directory and ADD to existing files
  int dir_files = read_files(dir_path, files + num_files, config.container_uid,
                             config.container_gid);
  if (dir_files < 0) {
    free(files);
    fclose(bin_file);
    exit(EXIT_FAILURE);
  }
  num_files += dir_files; // Add directory files to total count

  if (input_bin_file) {
    FILE *input_bin = fopen(input_bin_file, "rb");
    if (input_bin == NULL) {
      perror("Error opening input bin file");
      free(files);
      fclose(bin_file);
      exit(EXIT_FAILURE);
    }

    ContainerConfig input_config;
    fread(&input_config, sizeof(ContainerConfig), 1, input_bin);

    int input_num_files;
    fread(&input_num_files, sizeof(int), 1, input_bin);

    for (int i = 0; i < input_num_files && (num_files + i) < MAX_FILES; i++) {
      File *file = &files[num_files + i];
      fread(file->name, sizeof(char), MAX_PATH_LEN, input_bin);
      fread(&file->size, sizeof(size_t), 1, input_bin);
      file->data = malloc(file->size);
      if (file->data == NULL) {
        perror("Error allocating memory for file data");
        fclose(input_bin);
        free(files);
        fclose(bin_file);
        exit(EXIT_FAILURE);
      }
      fread(file->data, 1, file->size, input_bin);
    }

    num_files += input_num_files; // Add bin file contents to total count
    fclose(input_bin);
  }

  printf("Total files in container: %d\n", num_files);

  fwrite(&config, sizeof(ContainerConfig), 1, bin_file);
  fwrite(&num_files, sizeof(int), 1, bin_file);

  // Display the progress bar
  int progress_bar_width = 50;
  printf("Containerizing [");
  fflush(stdout);

  for (int i = 0; i < num_files; i++) {
    fwrite(files[i].name, sizeof(char), MAX_PATH_LEN, bin_file);
    fwrite(&files[i].size, sizeof(size_t), 1, bin_file);
    fwrite(files[i].data, 1, files[i].size, bin_file);
    free(files[i].data);

    // Update the progress bar
    int progress = (i + 1) * progress_bar_width / num_files;
    for (int j = 0; j < progress; j++) {
      printf("#");
      fflush(stdout);
    }
    for (int j = progress; j < progress_bar_width; j++) {
      printf(" ");
      fflush(stdout);
    }
    printf("] %d%%\r", (i + 1) * 100 / num_files);
    fflush(stdout);
  }

  printf("\n");

  free(files);
  fclose(bin_file);

  security_scan(output_file);
}

void *monitor_memory_usage(void *arg) {
  ContainerConfig *config = (ContainerConfig *)arg;
  mach_port_t task = mach_task_self();

  while (1) {
    task_vm_info_data_t vm_info;
    mach_msg_type_number_t count = TASK_VM_INFO_COUNT;

    if (task_info(task, TASK_VM_INFO, (task_info_t)&vm_info, &count) ==
        KERN_SUCCESS) {
      vm_size_t used_memory = vm_info.internal + vm_info.compressed;

      if (used_memory > config->memory_hard_limit) {
        fprintf(stderr,
                "Memory usage exceeded hard limit. Terminating process.\n");
        exit(1);
      } else if (used_memory > config->memory_soft_limit) {
        fprintf(stderr, "Warning: Memory usage exceeded soft limit. Clearing "
                        "cache memory.\n");
        system("purge");
      }
    }

    sleep(1);
  }
}

void apply_resource_limits(const ContainerConfig *config) {
  // Note it applies basic limits, as it doesn't fully use the kernel
  // The reason why is that it would cause many permission issues, pottentially
  // allow the containers to acces parts of the kernel they shouldn't be able to
  // access
  setpriority(PRIO_PROCESS, 0, config->cpu_priority);

  // Start memory monitoring thread
  pthread_t memory_thread;
  if (pthread_create(&memory_thread, NULL, monitor_memory_usage,
                     (void *)config) != 0) {
    perror("Failed to create memory monitoring thread");
  } else {
    printf("Memory monitoring started with soft limit %ld bytes and hard limit "
           "%ld bytes\n",
           config->memory_soft_limit, config->memory_hard_limit);
  }
}

ContainerNetwork load_container_network(const char *name) {
  ContainerNetwork network = {0};

  char filename[MAX_PATH_LEN];
  snprintf(filename, sizeof(filename), "/tmp/network_%s.conf", name);

  FILE *file = fopen(filename, "r");
  if (file == NULL) {
    fprintf(stderr, "Failed to load network configuration for %s\n", name);
    return network;
  }

  char line[256];
  while (fgets(line, sizeof(line), file)) {
    if (sscanf(line, "name=%s", network.name) == 1) {
      continue;
    }
    if (sscanf(line, "vlan_id=%d", &network.vlan_id) == 1) {
      continue;
    }
    if (sscanf(line, "container_name=%s",
               network.container_names[network.num_containers]) == 1) {
      network.num_containers++;
      continue;
    }
    if (sscanf(line, "container_ip=%s",
               network.container_ips[network.num_containers - 1]) == 1) {
      continue;
    }
  }

  fclose(file);
  return network;
}

void create_and_save_container_network(const char *name, int vlan_id,
                                       const char *allowed_ip) {
  ContainerNetwork network;
  strncpy(network.name, name, MAX_PATH_LEN - 1);
  network.name[MAX_PATH_LEN - 1] = '\0'; // Ensure null termination
  network.vlan_id = vlan_id;
  network.num_containers = 0;

  // Set allowed IP if provided, otherwise set to NULL or empty string
  char has_allowed_ip = (allowed_ip != NULL && strlen(allowed_ip) > 0);

  // Save the network configuration to a file
  char filename[MAX_PATH_LEN];
  snprintf(filename, sizeof(filename), "/tmp/network_%s.conf", name);
  FILE *file = fopen(filename, "w");
  if (file == NULL) {
    perror("Failed to save network configuration");
    return;
  }

  fprintf(file, "name=%s\n", network.name);
  fprintf(file, "vlan_id=%d\n", network.vlan_id);

  // Add the allowed IP to the configuration if specified
  if (has_allowed_ip) {
    fprintf(file, "allowed_ip=%s\n", allowed_ip);
    printf("Created and saved network %s with VLAN ID %d and restricted to IP "
           "%s\n",
           network.name, network.vlan_id, allowed_ip);
  } else {
    printf("Created and saved network %s with VLAN ID %d with no IP "
           "restrictions\n",
           network.name, network.vlan_id);
  }

  fclose(file);
}

void remove_container_network(const char *name) {
  char filename[MAX_PATH_LEN];
  snprintf(filename, sizeof(filename), "/tmp/network_%s.conf", name);

  if (remove(filename) == 0) {
    printf("Removed network %s\n", name);
  } else {
    perror("Failed to remove network");
  }
}

void add_container_to_network(ContainerNetwork *network,
                              const char *container_name) {
  if (network->num_containers < MAX_CLIENTS) {
    strncpy(network->container_names[network->num_containers], container_name,
            MAX_PATH_LEN - 1);

    // Dynamically assign IP address based on the number of containers
    char container_ip[16];
    snprintf(container_ip, sizeof(container_ip), "192.168.%d.%d",
             network->vlan_id, network->num_containers + 2);
    strncpy(network->container_ips[network->num_containers], container_ip, 15);

    network->num_containers++;

    // Save the updated network configuration to a file
    char filename[MAX_PATH_LEN];
    snprintf(filename, sizeof(filename), "/tmp/network_%s.conf", network->name);

    FILE *file = fopen(filename, "a");
    if (file == NULL) {
      perror("Failed to save network configuration");
      return;
    }

    fprintf(file, "container_name=%s\n", container_name);
    fprintf(file, "container_ip=%s\n", container_ip);
    fclose(file);
  }
}

char *get_ip_address() {
  int sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock == -1) {
    perror("socket");
    return NULL;
  }

  struct sockaddr_in loopback;
  memset(&loopback, 0, sizeof(loopback));
  loopback.sin_family = AF_INET;
  // Ping Google's DNS server
  loopback.sin_addr.s_addr = inet_addr("8.8.8.8");
  loopback.sin_port = htons(53);

  if (connect(sock, (struct sockaddr *)&loopback, sizeof(loopback)) == -1) {
    perror("connect");
    close(sock);
    return NULL;
  }

  struct sockaddr_in addr;
  socklen_t addr_len = sizeof(addr);
  if (getsockname(sock, (struct sockaddr *)&addr, &addr_len) == -1) {
    perror("getsockname");
    close(sock);
    return NULL;
  }

  close(sock);
  char *ip = strdup(inet_ntoa(addr.sin_addr));
  return ip;
}

void setup_pf_rules(ContainerNetwork *network) {
  char *ip_address = get_ip_address();
  if (ip_address == NULL) {
    fprintf(stderr, "Failed to get IP address\n");
    return;
  }

  // Assign IP address to the VLAN interface
  char ip_cmd[256];
  snprintf(ip_cmd, sizeof(ip_cmd),
           "ifconfig vlan%d create vlan %d vlandev en0 && ifconfig vlan%d inet "
           "%s/24 up",
           network->vlan_id, network->vlan_id, network->vlan_id, ip_address);
  system(ip_cmd);

  // Create a new file for VLAN rules
  char vlan_rules_file[64];
  snprintf(vlan_rules_file, sizeof(vlan_rules_file), "/etc/pf.vlan%d.conf",
           network->vlan_id);

  FILE *vlan_pf_conf = fopen(vlan_rules_file, "w");
  if (vlan_pf_conf == NULL) {
    perror("Failed to create VLAN rules file");
    free(ip_address);
    return;
  }

  // Write the VLAN rules to the new file
  fprintf(vlan_pf_conf,
          "# VLAN %d rules\n"
          "nat on en0 from %s/24 to any -> (en0)\n"
          "pass on vlan%d all\n"
          "pass in on vlan%d all\n"
          "pass out on vlan%d all\n",
          network->vlan_id, ip_address, network->vlan_id, network->vlan_id,
          network->vlan_id);
  fclose(vlan_pf_conf);

  // Add include statement to main pf.conf if not already present
  char include_cmd[256];
  snprintf(include_cmd, sizeof(include_cmd),
           "grep -q 'include \"%s\"' /etc/pf.conf || echo 'include \"%s\"' >> "
           "/etc/pf.conf",
           vlan_rules_file, vlan_rules_file);
  system(include_cmd);

  // Reload only the VLAN rules
  char reload_cmd[256];
  snprintf(reload_cmd, sizeof(reload_cmd), "pfctl -f %s", vlan_rules_file);
  system(reload_cmd);

  // Enable pf if it's not already enabled
  system("pfctl -e");

  free(ip_address);
}

void setup_network_isolation(ContainerConfig *config,
                             ContainerNetwork *network) {
  if (strcmp(config->network_mode, "bridge") == 0) {
    config->vlan_id = network->vlan_id;

    // Dynamically assign IP address based on the number of containers
    char container_ip[16];
    snprintf(container_ip, sizeof(container_ip), "192.168.%d.%d",
             network->vlan_id, network->num_containers + 2);
    add_container_to_network(network, config->name);

    printf("Setting up bridge network. Container %s on VLAN %d with IP %s\n",
           config->name, config->vlan_id, container_ip);

    char vlan_cmd[256];
    snprintf(vlan_cmd, sizeof(vlan_cmd),
             "ifconfig vlan%d create vlan %d vlandev en0", config->vlan_id,
             config->vlan_id);
    system(vlan_cmd);

    snprintf(vlan_cmd, sizeof(vlan_cmd), "ifconfig vlan%d inet %s/24 up",
             config->vlan_id, container_ip);
    system(vlan_cmd);
  } else if (strcmp(config->network_mode, "host") == 0) {
    printf("Using host network mode\n");
  } else if (strcmp(config->network_mode, "none") == 0) {
    printf("Network isolation set to none\n");
  } else {
    printf("Unsupported network mode\n");
  }
}

void enable_container_communication(ContainerNetwork *network) {
  char pf_rule[256];
  snprintf(pf_rule, sizeof(pf_rule), "pass on vlan%d all\n", network->vlan_id);

  // Append the rule to pf.conf
  FILE *pf_conf = fopen("/etc/pf.conf", "a");
  if (pf_conf == NULL) {
    perror("Failed to open /etc/pf.conf");
    return;
  }
  fprintf(pf_conf, "%s", pf_rule);
  fclose(pf_conf);

  // Reload pf rules
  system("pfctl -f /etc/pf.conf");
}

void handle_client(int client_socket, const char *container_root) {
  char command[MAX_COMMAND_LEN];
  ssize_t bytes_received;

  while ((bytes_received =
              recv(client_socket, command, sizeof(command) - 1, 0)) > 0) {
    command[bytes_received] = '\0';

    if (strcmp(command, "break") == 0) {
      break;
    }

    // Execute the command
    execute_command(command, container_root);

    // Send a response back to the client
    const char *response = "Command executed.\n";
    send(client_socket, response, strlen(response), 0);
  }

  close(client_socket);
}

void start_network_listener(const char *container_root) {
  int server_fd, client_socket;
  struct sockaddr_in address;
  int opt = 1;
  int addrlen = sizeof(address);

  // Create socket file descriptor
  if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
    perror("socket failed");
    exit(EXIT_FAILURE);
  }

  // Allow reuse of local addresses (SO_REUSEADDR) - this is required on macOS
  if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
    perror("setsockopt(SO_REUSEADDR) failed");
    exit(EXIT_FAILURE);
  }

  // Bind the socket to the network address and port
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = INADDR_ANY;
  address.sin_port = htons(port);
  if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
    perror("bind failed");
    exit(EXIT_FAILURE);
  }

  // Start listening for incoming connections
  if (listen(server_fd, MAX_CLIENTS) < 0) {
    perror("listen");
    exit(EXIT_FAILURE);
  }

  printf("Server listening on port %d\n", port);

  while (1) {
    if ((client_socket = accept(server_fd, (struct sockaddr *)&address,
                                (socklen_t *)&addrlen)) < 0) {
      perror("accept");
      continue;
    }

    printf("New client connected\n");
    handle_client(client_socket, container_root);
  }
}

void *network_listener_entry(void *arg) {
  // Cast the argument back to its original type
  char *container_root_arg = (char *)arg;

  // Call the actual listener function with the correct argument
  start_network_listener(container_root_arg);

  // Although start_network_listener has an infinite loop, it's good practice
  // to include cleanup code in case the function is ever changed to return.
  free(container_root_arg);
  return NULL;
}

void scale_container_resources(long memory_soft_limit, long memory_hard_limit,
                               int cpu_priority) {
  ContainerConfig config;
  // Update the container configuration
  config.memory_soft_limit = memory_soft_limit;
  config.memory_hard_limit = memory_hard_limit;
  config.cpu_priority = cpu_priority;

  // Apply the new resource limits
  apply_resource_limits(&config);

  printf("Container resources.sh scaled:\n");
  printf("Memory Soft Limit: %ld bytes\n", memory_soft_limit);
  printf("Memory Hard Limit: %ld bytes\n", memory_hard_limit);
  printf("CPU Priority: %d\n", cpu_priority);
}

void handle_script_command(const char *script_content) {
  execute_script(script_content);
}

void handle_script_file(const char *filename) { execute_script_file(filename); }

void create_shared_folder() {
  struct stat st = {0};
  if (stat(SHARED_FOLDER_PATH, &st) == -1) {
    mkdir(SHARED_FOLDER_PATH, 0755);
  }
}

void create_directories(const char *file_path) {
  char path[MAX_PATH_LEN];
  strncpy(path, file_path, MAX_PATH_LEN);

  for (char *p = path + 1; *p; p++) {
    if (*p == '/') {
      *p = '\0';
      mkdir(path, 0755);
      *p = '/';
    }
  }
}

double get_cpu_usage() {
  static clock_t last_cpu_time = 0;
  static struct timeval last_wall_time = {0};

  struct rusage usage;
  struct timeval current_wall_time;

  getrusage(RUSAGE_SELF, &usage);
  gettimeofday(&current_wall_time, NULL);

  clock_t current_cpu_time =
      usage.ru_utime.tv_sec * 1000000 + usage.ru_utime.tv_usec +
      usage.ru_stime.tv_sec * 1000000 + usage.ru_stime.tv_usec;

  double cpu_usage = 0.0;
  if (last_cpu_time != 0) {
    long wall_time_diff =
        (current_wall_time.tv_sec - last_wall_time.tv_sec) * 1000000 +
        (current_wall_time.tv_usec - last_wall_time.tv_usec);

    long cpu_time_diff = current_cpu_time - last_cpu_time;

    cpu_usage = (cpu_time_diff * 100.0) / wall_time_diff;
  }

  last_cpu_time = current_cpu_time;
  last_wall_time = current_wall_time;

  return cpu_usage;
}

void *auto_scale_resources(void *arg) {
  ContainerConfig *config = (ContainerConfig *)arg;
  struct rusage usage;
  long memory_increment = 100 * 1024 * 1024; // 100 MB
  int cpu_priority_increment = 1;
  int scale_count = 0;

  while (1) {
    if (getrusage(RUSAGE_SELF, &usage) == 0) {
      long memory_used = usage.ru_maxrss;
      double memory_usage_percent =
          (memory_used * 100.0) / config->memory_soft_limit;
      double cpu_usage = get_cpu_usage();

      bool should_scale = false;

      if (memory_usage_percent > MEMORY_USAGE_THRESHOLD &&
          config->memory_soft_limit < MAX_MEMORY_LIMIT) {
        config->memory_soft_limit += memory_increment;
        config->memory_hard_limit += memory_increment;
        should_scale = true;
      }

      if (cpu_usage > CPU_USAGE_THRESHOLD &&
          config->cpu_priority > MIN_CPU_PRIORITY) {
        config->cpu_priority =
            (config->cpu_priority > MIN_CPU_PRIORITY + cpu_priority_increment)
                ? config->cpu_priority - cpu_priority_increment
                : MIN_CPU_PRIORITY;
        should_scale = true;
      }

      if (should_scale) {
        apply_resource_limits(config);
        scale_count++;

        printf("Auto-scaled resources (Count: %d):\n", scale_count);
        printf("Memory Usage: %.2f%% (%ld / %ld bytes)\n", memory_usage_percent,
               memory_used, config->memory_soft_limit);
        printf("CPU Usage: %.2f%%\n", cpu_usage);
        printf("New Memory Soft Limit: %ld bytes\n", config->memory_soft_limit);
        printf("New Memory Hard Limit: %ld bytes\n", config->memory_hard_limit);
        printf("New CPU Priority: %d\n", config->cpu_priority);
      }
    }

    sleep(5);
  }
}

void start_auto_scaling(ContainerConfig *config) {
  pthread_t auto_scale_thread;
  if (pthread_create(&auto_scale_thread, NULL, auto_scale_resources,
                     (void *)config) != 0) {
    perror("Failed to create auto-scaling thread");
  } else {
    printf("Auto-scaling started\n");
  }
}

void print_current_resource_usage(ContainerConfig *config) {
  struct rusage usage;
  if (getrusage(RUSAGE_SELF, &usage) == 0) {
    long memory_used = usage.ru_maxrss;
    double memory_usage_percent =
        (memory_used * 100.0) / config->memory_soft_limit;
    double cpu_usage = get_cpu_usage();

    printf("Current Resource Usage:\n");
    printf("Memory Usage: %.2f%% (%ld / %ld bytes)\n", memory_usage_percent,
           memory_used, config->memory_soft_limit);
    printf("CPU Usage: %.2f%%\n", cpu_usage);
    printf("CPU Priority: %d\n", config->cpu_priority);
  } else {
    perror("Failed to get resource usage");
  }
}

void set_terminal_raw_mode() {
  struct termios raw;
  tcgetattr(STDIN_FILENO, &raw);
  raw.c_lflag &= ~(ICANON | ECHO);
  tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);
}

void set_terminal_canonical_mode() {
  struct termios canonical;
  tcgetattr(STDIN_FILENO, &canonical);
  canonical.c_lflag |= (ICANON | ECHO);
  tcsetattr(STDIN_FILENO, TCSAFLUSH, &canonical);
}

void move_cursor_left(int n) {
  printf("\033[%dD", n);
  fflush(stdout);
}

void move_cursor_right(int n) {
  printf("\033[%dC", n);
  fflush(stdout);
}

void clear_line() {
  printf("\033[2K");
  fflush(stdout);
}

void add_to_history(const char *command) {
  if (history.count < MAX_HISTORY_LEN) {
    strncpy(history.commands[history.count], command, MAX_COMMAND_LEN);
    history.count++;
    history.current = history.count;
  } else {
    // Shift the history to make room for the new command
    memmove(history.commands, history.commands + 1,
            (MAX_HISTORY_LEN - 1) * MAX_COMMAND_LEN);
    strncpy(history.commands[MAX_HISTORY_LEN - 1], command, MAX_COMMAND_LEN);
  }
}

void navigate_history(char *command, int *command_index, int *cursor_pos,
                      int direction) {
  if (direction == -1 && history.current > 0) {
    history.current--;
    strncpy(command, history.commands[history.current], MAX_COMMAND_LEN);
    *command_index = strlen(command);
    *cursor_pos = *command_index;
  } else if (direction == 1 && history.current < history.count - 1) {
    history.current++;
    strncpy(command, history.commands[history.current], MAX_COMMAND_LEN);
    *command_index = strlen(command);
    *cursor_pos = *command_index;
  }
}

volatile sig_atomic_t stop_thread = 0;

void signal_handler() { stop_thread = 1; }

void *logger_thread(void *arg) {
  FILE *log_file = fopen("/Volumes/Container/var/log/log.txt", "w");
  if (log_file == NULL) {
    perror("Failed to open log file");
    return NULL;
  }

  while (!stop_thread) {
    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage) == 0) {
      long memory_used = usage.ru_maxrss;
      double cpu_usage = get_cpu_usage();

      fprintf(log_file, "Memory Usage: %ld bytes\n", memory_used);
      fprintf(log_file, "CPU Usage: %.2f%%\n", cpu_usage);
      fprintf(log_file, "CPU Priority: %d\n",
              ((ContainerConfig *)arg)->cpu_priority);

    } else {
      perror("Failed to get resource usage");
    }

    sleep(5);
  }

  fclose(log_file);
  return NULL;
}

volatile sig_atomic_t should_exit = 0;

void handle_signal(int sig) {
  // Set the should_exit flag when a signal is received
  if (sig == SIGTERM || sig == SIGINT || sig == SIGSEGV) {
    should_exit = 1;
  }
}

typedef struct {
  pthread_t thread;
  pid_t pid; // Add process ID
  char command[MAX_COMMAND_LEN];
  int is_running;
  int is_paused;
  int exit_code;
  char output[4096];
  pthread_mutex_t output_mutex;
  pthread_cond_t pause_cond;
  char container_root[MAX_PATH_LEN];
  time_t start_time; // Add start time
} BackgroundTask;

typedef struct {
  BackgroundTask tasks[MAX_BACKGROUND_THREADS];
  int task_count;
  pthread_mutex_t tasks_mutex;
} BackgroundTaskManager;

BackgroundTaskManager bg_manager = {.task_count = 0,
                                    .tasks_mutex = PTHREAD_MUTEX_INITIALIZER};

// Modify the thread function to store the process ID
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

// Global variable declaration for the attach interrupt flag
volatile sig_atomic_t attach_interrupted = 0;

// Signal handler for attaching to processes
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

typedef struct {
  char command[MAX_COMMAND_LEN];
  time_t scheduled_time; // Time at which the command should be executed
} ScheduledTask;

ScheduledTask scheduled_tasks[MAX_SCHEDULED_TASKS];
int num_scheduled_tasks = 0;

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

void create_fake_system_files(const char *container_root) {
  char path_buffer[MAX_PATH_LEN];

  // Create essential directories
  const char *essential_dirs[] = {"etc", "tmp", "var", "var/log"};

  for (int i = 0; i < sizeof(essential_dirs) / sizeof(essential_dirs[0]); i++) {
    snprintf(path_buffer, sizeof(path_buffer), "%s/%s", container_root,
             essential_dirs[i]);
    mkdir(path_buffer, 0755);
  }

  // Create /etc/passwd
  snprintf(path_buffer, sizeof(path_buffer), "%s/etc/passwd", container_root);
  FILE *passwd_file = fopen(path_buffer, "w");
  if (passwd_file) {
    fprintf(passwd_file, "root:x:0:0:root:/root:/bin/bash\n");
    fprintf(passwd_file, "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n");
    fprintf(passwd_file, "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n");
    fprintf(passwd_file, "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n");
    fprintf(passwd_file,
            "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n");
    fclose(passwd_file);
  }

  // Create /etc/group
  snprintf(path_buffer, sizeof(path_buffer), "%s/etc/group", container_root);
  FILE *group_file = fopen(path_buffer, "w");
  if (group_file) {
    fprintf(group_file, "root:x:0:\n");
    fprintf(group_file, "daemon:x:1:\n");
    fprintf(group_file, "bin:x:2:\n");
    fprintf(group_file, "sys:x:3:\n");
    fprintf(group_file, "nogroup:x:65534:\n");
    fclose(group_file);
  }

  // Create /etc/hostname
  snprintf(path_buffer, sizeof(path_buffer), "%s/etc/hostname", container_root);
  FILE *hostname_file = fopen(path_buffer, "w");
  if (hostname_file) {
    fprintf(hostname_file, "container\n");
    fclose(hostname_file);
  }

  // Create basic /etc/os-release or equivalent for macOS
  snprintf(path_buffer, sizeof(path_buffer), "%s/etc/os-release",
           container_root);
  FILE *os_file = fopen(path_buffer, "w");
  if (os_file) {
    fprintf(os_file, "NAME=\"Osxiec Container OS\"\n");
    fprintf(os_file, "VERSION=\"1.0\"\n");
    fprintf(os_file, "ID=container\n");
    fclose(os_file);
  }
}

void set_container_env(const char *key, const char *value) {
  // Check if variable exists
  for (int i = 0; i < container_state.num_env_vars; i++) {
    if (strstr(container_state.environment_variables[i], key) ==
        container_state.environment_variables[i]) {
      char *eq = strchr(container_state.environment_variables[i], '=');
      if (eq && strcmp(eq + 1, value) != 0) {
        free(container_state.environment_variables[i]);
        container_state.environment_variables[i] =
            malloc(strlen(key) + strlen(value) + 2);
        sprintf(container_state.environment_variables[i], "%s=%s", key, value);
      }
      return;
    }
  }

  // Add new variable
  container_state.num_env_vars++;
  container_state.environment_variables =
      realloc(container_state.environment_variables,
              container_state.num_env_vars * sizeof(char *));
  container_state.environment_variables[container_state.num_env_vars - 1] =
      malloc(strlen(key) + strlen(value) + 2);
  sprintf(
      container_state.environment_variables[container_state.num_env_vars - 1],
      "%s=%s", key, value);
}

int create_container_user(const char *username, const char *container_root,
                          uid_t *uid) {
  char command[1024];

  // Create the user with dscl
  snprintf(command, sizeof(command),
           "dscl . -create /Users/%s && "
           "dscl . -create /Users/%s UserShell /bin/bash && "
           "dscl . -create /Users/%s RealName \"Container User %s\" && "
           "dscl . -create /Users/%s UniqueID %d && "
           "dscl . -create /Users/%s PrimaryGroupID 20 && "
           "dscl . -create /Users/%s NFSHomeDirectory %s && "
           "dscl . -passwd /Users/%s container_temp_pass",
           username, username, username, username, username, *uid, username,
           username, container_root, username);

  if (system(command) != 0) {
    fprintf(stderr, "Failed to create container user\n");
    return -1;
  }

  printf("Created container user: %s (UID: %d)\n", username, *uid);
  return 0;
}

int launch_container_as_user(const char *username, const char *bin_file_path,
                             const char *container_root) {
  char plist_path[512];
  char plist_content[2048];

  // Create a temporary launch agent plist
  snprintf(plist_path, sizeof(plist_path), "/tmp/container_%s.plist", username);

  snprintf(plist_content, sizeof(plist_content),
           "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
           "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" "
           "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
           "<plist version=\"1.0\">\n"
           "<dict>\n"
           "    <key>Label</key>\n"
           "    <string>com.container.%s</string>\n"
           "    <key>ProgramArguments</key>\n"
           "    <array>\n"
           "        <string>/bin/bash</string>\n"
           "        <string>-c</string>\n"
           "        <string>cd %s && exec /bin/bash</string>\n"
           "    </array>\n"
           "    <key>WorkingDirectory</key>\n"
           "    <string>%s</string>\n"
           "    <key>StandardOutPath</key>\n"
           "    <string>/tmp/container_%s.log</string>\n"
           "    <key>StandardErrorPath</key>\n"
           "    <string>/tmp/container_%s.err</string>\n"
           "</dict>\n"
           "</plist>\n",
           username, container_root, container_root, username, username);

  FILE *plist_file = fopen(plist_path, "w");
  if (!plist_file) {
    perror("Failed to create plist file");
    return -1;
  }

  fprintf(plist_file, "%s", plist_content);
  fclose(plist_file);

  // Get user info for launchctl asuser
  struct passwd *pwd = getpwnam(username);
  if (!pwd) {
    fprintf(stderr, "Failed to get user info for %s\n", username);
    return -1;
  }

  // Launch the container process as the dedicated user
  char launch_command[1024];
  snprintf(launch_command, sizeof(launch_command),
           "launchctl asuser %d launchctl load %s", pwd->pw_uid, plist_path);

  if (system(launch_command) != 0) {
    fprintf(stderr, "Failed to launch container as user %s\n", username);
    return -1;
  }

  printf("Container launched as user %s\n", username);
  return 0;
}

// Simple arc4 cipher for encrypting/decrypting data.
// The same function encrypts and decrypts.
// NOTE: This is for obfuscation, not strong cryptographic security.
void arc4_cipher(char *data, size_t data_len, const char *key) {
  unsigned char S[256];
  unsigned int i, j;
  size_t key_len = strlen(key);

  if (key_len == 0) {
    return; // Cannot operate with an empty key
  }

  // --- Key-Scheduling Algorithm (KSA) ---
  // Initialize the state array S
  for (i = 0; i < 256; i++) {
    S[i] = i;
  }

  // Use the key to shuffle the state array
  for (i = 0, j = 0; i < 256; i++) {
    j = (j + S[i] + key[i % key_len]) % 256;
    // Swap S[i] and S[j]
    unsigned char temp = S[i];
    S[i] = S[j];
    S[j] = temp;
  }

  // --- Pseudo-random Generation Algorithm (PRGA) & XORing ---
  // Reset indices to generate the keystream and apply it
  i = 0;
  j = 0;
  for (size_t n = 0; n < data_len; n++) {
    i = (i + 1) % 256;
    j = (j + S[i]) % 256;

    // Swap S[i] and S[j]
    unsigned char temp = S[i];
    S[i] = S[j];
    S[j] = temp;

    // Generate the keystream byte
    unsigned char keystream_byte = S[(S[i] + S[j]) % 256];

    // XOR the data byte with the keystream byte
    data[n] = data[n] ^ keystream_byte;
  }
}

void handle_secret_command(const char *args) {
  char key[MAX_VAR_LEN];
  char var_assignment[MAX_VAR_LEN];
  char var_name[MAX_VAR_LEN];

  if (sscanf(args, "%s %s", key, var_assignment) != 2) {
    printf("Usage: secret <key> <VARIABLE_NAME>=<value>\n");
    return;
  }

  char *eq_ptr = strchr(var_assignment, '=');
  if (eq_ptr == NULL) {
    printf("Invalid format. Use VARIABLE_NAME=value.\n");
    return;
  }

  // Separate the name and the value
  size_t name_len = eq_ptr - var_assignment;
  if (name_len >= MAX_VAR_LEN) {
    printf("Error: Variable name is too long.\n");
    return;
  }
  strncpy(var_name, var_assignment, name_len);
  var_name[name_len] = '\0';

  char *value = eq_ptr + 1;
  size_t value_len = strlen(value);

  if (container_state.num_secrets >= MAX_SECRETS) {
    printf("Error: Maximum number of secrets reached.\n");
    return;
  }

  // Check if secret already exists and overwrite it
  for (int i = 0; i < container_state.num_secrets; i++) {
    if (strcmp(container_state.secrets[i].name, var_name) == 0) {
      free(container_state.secrets[i].encrypted_value);
      // Re-use this slot
      char *encrypted_val = strdup(value);
      arc4_cipher(encrypted_val, value_len, key);

      container_state.secrets[i].encrypted_value = encrypted_val;
      container_state.secrets[i].length = value_len;
      printf("Secret '%s' updated.\n", var_name);
      return;
    }
  }

  // Add a new secret
  int i = container_state.num_secrets;
  strncpy(container_state.secrets[i].name, var_name, MAX_VAR_LEN - 1);
  container_state.secrets[i].name[MAX_VAR_LEN - 1] = '\0';

  char *encrypted_val = strdup(value);
  if (!encrypted_val) {
    perror("Failed to allocate memory for secret");
    return;
  }

  arc4_cipher(encrypted_val, value_len, key);

  container_state.secrets[i].encrypted_value = encrypted_val;
  container_state.secrets[i].length = value_len;
  container_state.num_secrets++;

  printf("Secret '%s' set.\n", var_name);
}

void handle_getsecret_command(const char *args) {
  char key[MAX_VAR_LEN];
  char var_name[MAX_VAR_LEN];

  if (sscanf(args, "%s %s", key, var_name) != 2) {
    printf("Usage: getsecret <key> <VARIABLE_NAME>\n");
    return;
  }

  for (int i = 0; i < container_state.num_secrets; i++) {
    if (strcmp(container_state.secrets[i].name, var_name) == 0) {
      // Create a temporary copy to decrypt
      char *decrypted_value =
          (char *)malloc(container_state.secrets[i].length + 1);
      if (!decrypted_value) {
        perror("Failed to allocate memory for decryption");
        return;
      }
      memcpy(decrypted_value, container_state.secrets[i].encrypted_value,
             container_state.secrets[i].length);

      // Decrypt the copy
      arc4_cipher(decrypted_value, container_state.secrets[i].length, key);
      decrypted_value[container_state.secrets[i].length] = '\0';

      // Print to stdout (without a newline for command substitution)
      printf("%s", decrypted_value);

      free(decrypted_value);
      return;
    }
  }

  // Do not print an error to stderr to avoid cluttering command substitution
  // uncomment this if debugging fprintf(stderr, "Error: Secret '%s' not
  // found.\n", var_name);
}

void save_container_state(FILE *state_file, const ContainerConfig *config,
                          const ContainerState *state) {
  if (state_file == NULL) {
    perror("Cannot save state to a NULL file pointer");
    return;
  }

  // 1. Save the main container configuration
  fwrite(config, sizeof(ContainerConfig), 1, state_file);

  // 2. Save environment variables correctly
  fwrite(&state->num_env_vars, sizeof(int), 1, state_file);
  for (int i = 0; i < state->num_env_vars; i++) {
    size_t len =
        strlen(state->environment_variables[i]) + 1; // Include null terminator
    fwrite(&len, sizeof(size_t), 1, state_file);     // Write length
    fwrite(state->environment_variables[i], 1, len, state_file); // Write data
  }

  // 3. Save secrets correctly
  fwrite(&state->num_secrets, sizeof(int), 1, state_file);
  for (int i = 0; i < state->num_secrets; i++) {
    const SecretVariable *secret = &state->secrets[i];

    // Write the secret's name
    fwrite(secret->name, sizeof(char), MAX_VAR_LEN, state_file);

    // Write the length of the encrypted value
    fwrite(&secret->length, sizeof(size_t), 1, state_file);

    // Write the encrypted value data itself
    if (secret->length > 0) {
      fwrite(secret->encrypted_value, 1, secret->length, state_file);
    }
  }

  printf("Container state, including %d secrets, saved successfully.\n",
         state->num_secrets);
}

void create_isolated_environment(FILE *bin_file, const char *bin_file_path,
                                 ContainerNetwork *network) {
  signal(SIGTERM, handle_signal);
  signal(SIGINT, handle_signal);
  signal(SIGSEGV, handle_signal);

  // Create dedicated container user
  char container_username[64];
  snprintf(container_username, sizeof(container_username), "container_%d",
           getpid());
  ContainerConfig config;
  fread(&config, sizeof(ContainerConfig), 1, bin_file);

  if (create_container_user(container_username, "/tmp",
                            &config.container_uid) != 0) {
    fprintf(stderr,
            "Failed to create container user, falling back to current user\n");
  }

  setup_network_isolation(&config, network);
  enable_container_communication(network);

  int num_files;
  fread(&num_files, sizeof(int), 1, bin_file);

  // Create shared folder if it doesn't exist
  char shared_folder_path[] = "/Volumes/SharedContainer";
  mkdir(shared_folder_path, 0755);

  // Create and mount disk image for file system isolation
  char disk_image_path[MAX_PATH_LEN];
  snprintf(disk_image_path, sizeof(disk_image_path),
           "/tmp/container_disk_%d.dmg", getpid());

  // Assign the volume name as the bin_file_path
  char create_disk_command[MAX_COMMAND_LEN];
  struct stat st;
  if (stat(bin_file_path, &st) == -1) {
    perror("stat");
  }

  // Get the size of the file in bytes
  off_t file_size = st.st_size;

  // Convert the size to gigabytes and add 1 GB
  double size_in_gb = (double)file_size / (1024 * 1024 * 1024) + 1.0;

  // Format the size to two decimal places
  snprintf(create_disk_command, sizeof(create_disk_command),
           "hdiutil create -size %.2fg -fs HFS+ -volname \"%s\" %s", size_in_gb,
           bin_file_path, disk_image_path);
  system(create_disk_command);
  chmod(disk_image_path, 0644); // rw-r--r--

  char mount_command[MAX_COMMAND_LEN];
  snprintf(mount_command, sizeof(mount_command), "hdiutil attach %s",
           disk_image_path);
  system(mount_command);

  char container_root[MAX_PATH_LEN];
  snprintf(container_root, sizeof(container_root), "/Volumes/%s",
           bin_file_path);

  // Create a symbolic link to the shared folder
  char shared_mount_point[MAX_PATH_LEN];
  snprintf(shared_mount_point, sizeof(shared_mount_point), "%s/shared",
           container_root);
  symlink(shared_folder_path, shared_mount_point);

  // Extract files
  for (int i = 0; i < num_files; i++) {
    File file;
    fread(file.name, sizeof(char), MAX_PATH_LEN, bin_file);
    fread(&file.size, sizeof(size_t), 1, bin_file);
    file.data = malloc(file.size);
    if (file.data == NULL) {
      perror("Error allocating memory for file data");
      exit(EXIT_FAILURE);
    }
    fread(file.data, 1, file.size, bin_file);
    char file_path[MAX_PATH_LEN];
    snprintf(file_path, sizeof(file_path), "%s/%s", container_root, file.name);

    // Ensure all necessary directories exist
    create_directories(file_path);
    FILE *out_file = fopen(file_path, "wb");
    if (out_file == NULL) {
      perror("Error creating file in container");
      exit(EXIT_FAILURE);
    }
    fwrite(file.data, 1, file.size, out_file);
    fclose(out_file);
    free(file.data);
    chmod(file_path, 0755);
  }

  link_system_directories(container_root);
  chmod(container_root, 0755);

  // Set ownership of container root to the dedicated user
  char chown_command[MAX_COMMAND_LEN];
  snprintf(chown_command, sizeof(chown_command), "chown -R %d:%d %s",
           config.container_uid, config.container_gid, container_root);
  system(chown_command);

  if (launch_container_as_user(container_username, bin_file_path,
                               container_root) != 0) {
    fprintf(stderr, "Failed to launch container as user %s\n",
            container_username);
    exit(1);
  }

  if (chdir(container_root) != 0) {
    perror("Failed to change to container root directory");
    exit(1);
  }

  if (setgid(config.container_gid) != 0) {
    perror("Failed to set group ID");
    exit(1);
  }

  if (setuid(config.container_uid) != 0) {
    perror("Failed to set user ID");
    exit(1);
  }

  create_fake_system_files(container_root);
  apply_resource_limits(&config);

  char sandbox_profile[2048];
  snprintf(sandbox_profile, sizeof(sandbox_profile),
           "(version 1)"
           "(deny default)"
           "(allow process-fork)"
           "(allow file-read*)"
           "(allow file-write* (subpath \"%s\"))"
           "(allow file-read* (subpath \"%s\"))"
           "(allow file-read* (literal \"%s\"))"
           "(allow file-read* (subpath \"/usr\"))"
           "(deny file-read* (subpath \"/usr/local\"))"
           "(allow file-read* (subpath \"/bin\"))"
           "(allow file-read* (subpath \"/sbin\"))"
           "(allow file-read* (subpath \"/dev\"))"
           "(allow file-read* (subpath \"/System\"))"
           "(allow file-read* (subpath \"%s\"))"
           "(allow file-read* (subpath \"/Applications/Xcode.app\"))"
           "(allow file-write* (subpath \"%s\"))"
           "(allow network-outbound (remote ip))"
           "(allow network-inbound (local ip))"
           "(allow process-exec (subpath \"/usr\"))"
           "(deny process-exec (subpath \"/usr/local\"))"
           "(allow process-exec (subpath \"/Applications/Xcode.app\"))"
           "(allow process-exec (subpath \"/bin\"))"
           "(allow process-exec (subpath \"/bin\"))"
           "(allow process-exec (subpath \"/sbin\"))"
           "(allow process-exec (subpath \"/dev\"))"
           "(allow process-exec (subpath \"%s\"))",
           container_root, container_root, bin_file_path, shared_mount_point,
           shared_mount_point, container_root);

  char *error;
  if (sandbox_init(sandbox_profile, 0, &error) != 0) {
    fprintf(stderr, "sandbox_init failed: %s\n", error);
    sandbox_free_error(error);
    exit(1);
  }

  printf("\n=== Container %s Terminal (User: %s) ===\n", bin_file_path,
         container_username);
  printf("Enter commands (type 'exit' to quit, help for help):\n");
  printf("If you just ran the container ignore the first log file error");

  // Start the network listener in a separate thread
  pthread_t network_thread;
  if (pthread_create(&network_thread, NULL,
                     (void *(*)(void *))start_network_listener, NULL) != 0) {
    perror("Failed to create network listener thread");
  }

  if (config.start_config[0] != '\0') {
    char start_config_path[MAX_PATH_LEN];
    snprintf(start_config_path, sizeof(start_config_path), "%s/%s",
             container_root, config.start_config);
    execute_start_config(start_config_path, container_root);
  }

  char command[MAX_COMMAND_LEN];
  int command_index = 0;
  int cursor_pos = 0;
  set_terminal_raw_mode();
  pthread_t logger;
  pthread_create(&logger, NULL, logger_thread, &config);
  int network_thread_active = 1;

  while (1) {
    if (should_exit) {
      break;
    }

    check_scheduled_tasks(container_root);

    printf("> ");
    fflush(stdout);
    int ch;
    while ((ch = getchar()) != EOF) {
      if (ch == 27) {    // ESC key
        getchar();       // Skip the next character
        ch = getchar();  // Get the actual key code
        if (ch == 'A') { // Up arrow
          navigate_history(command, &command_index, &cursor_pos, -1);
        } else if (ch == 'B') { // Down arrow
          navigate_history(command, &command_index, &cursor_pos, 1);
        } else if (ch == 'C') { // Right arrow
          if (cursor_pos < command_index) {
            move_cursor_right(1);
            cursor_pos++;
          }
        } else if (ch == 'D') { // Left arrow
          if (cursor_pos > 0) {
            move_cursor_left(1);
            cursor_pos--;
          }
        }
      } else if (ch == 127 || ch == 8) { // Backspace or Delete
        if (cursor_pos > 0) {
          move_cursor_left(1);
          clear_line();
          memmove(&command[cursor_pos - 1], &command[cursor_pos],
                  command_index - cursor_pos + 1);
          command_index--;
          cursor_pos--;
          printf("%s", &command[cursor_pos]);
          move_cursor_left(command_index - cursor_pos);
        }
      } else if (ch == '\n' || ch == '\r') { // Enter key
        command[command_index] = '\0';
        set_terminal_canonical_mode();
        usleep(10000); // 10ms delay
        if (strcmp(command, "exit") == 0)
          goto exit_loop;
        if (strcmp(command, "debug") == 0) {
          debug_mode = DEBUG_STEP;
          printf("Entered debug mode. Type 'help' for debug commands.\n");
        } else if (strncmp(command, "scale", 5) == 0) {
          long memory_soft_limit, memory_hard_limit;
          int cpu_priority;
          if (sscanf(command, "scale %ld %ld %d", &memory_soft_limit,
                     &memory_hard_limit, &cpu_priority) == 3) {
            scale_container_resources(memory_soft_limit, memory_hard_limit,
                                      cpu_priority);
          } else {
            printf("Usage: scale <memory_soft_limit> <memory_hard_limit> "
                   "<cpu_priority>\n");
          }
        } else if (strncmp(command, "xs", 6) == 0) {
          char *script_content = command + 7;
          handle_script_command(script_content);
        } else if (strncmp(command, "osxs", 4) == 0) {
          char *filename = command + 5;
          while (isspace(*filename)) {
            filename++;
          }
          handle_script_file(filename);
        } else if (strcmp(command, "autoscale") == 0) {
          start_auto_scaling(&config);
        } else if (strcmp(command, "status") == 0) {
          print_current_resource_usage(&config);
        } else if (strncmp(command, "br ", 3) ==
                   0) {            // Note the space after 'br'
          char *cmd = command + 3; // Skip "br " prefix
          while (isspace(*cmd))
            cmd++; // Skip any additional whitespace
          if (*cmd) {
            int task_id = start_background_task(cmd, container_root);
            if (task_id >= 0) {
              printf("Started background task %d: %s\n", task_id, cmd);
            } else {
              printf("Failed to start background task\n");
            }
          } else {
            printf("Usage: br <command>\n");
          }
        } else if (strcmp(command, "pause") == 0) {
          pause_background_tasks();
          printf("All background tasks paused\n");
        } else if (strcmp(command, "unpause") == 0) {
          unpause_background_tasks();
          printf("All background tasks unpaused\n");
        } else if (strncmp(command, "wait ", 5) == 0) {
          int task_id;
          if (sscanf(command + 5, "%d", &task_id) == 1) {
            wait_background_task(task_id);
          } else {
            printf("Usage: wait <task_id>\n");
          }
        } else if (strncmp(command, "wait", 4) == 0) {
          int task_id;
          if (sscanf(command + 5, "%d", &task_id) == 1) {
            wait_background_task(task_id);
          } else {
            printf("Usage: wait <task_id>\n");
          }
        } else if (strcmp(command, "ps") == 0) {
          show_background_tasks();
        } else if (strcmp(command, "network restart") == 0) {
          stop_network_thread(network_thread, network_thread_active);
          start_network_thread(network_thread, network_thread_active);
        } else if (strcmp(command, "network start") == 0) {
          start_network_thread(network_thread, network_thread_active);
        } else if (strcmp(command, "network stop") == 0) {
          stop_network_thread(network_thread, network_thread_active);
        } else if (strcmp(command, "network status") == 0) {
          printf("Network listener status: %s\n",
                 network_thread_active ? "running" : "stopped");
        } else if (strncmp(command, "trace ", 6) == 0) {
          char *cmd = command + 6; // Skip "trace " prefix
          while (isspace(*cmd))
            cmd++; // Skip any additional whitespace
          if (*cmd) {
            trace_command(cmd, container_root);
          } else {
            printf("Usage: trace <command>\n");
          }
        } else if (strncmp(command, "proctrace ", 10) == 0) {
          int process_id;
          if (sscanf(command + 10, "%d", &process_id) == 1) {
            trace_background_process(process_id, container_root);
          } else {
            printf("Usage: proctrace <process_id>\n");
          }
        } else if (strcmp(command, "cps") == 0) {
          live_process_inspection(container_root);
        } else if (strncmp(command, "attach ", 7) == 0) {
          int task_id;
          if (sscanf(command + 7, "%d", &task_id) == 1) {
            attach_to_background_task(task_id);
          } else {
            printf("Usage: attach <task_id>\n");
          }
        } else if (strncmp(command, "schedule", 8) == 0) {
          char *cmd = command + 9; // Skip "schedule " prefix
          while (isspace(*cmd))
            cmd++; // Skip any additional whitespace
          char *time_str = strtok(cmd, " ");
          char *event_str = strtok(NULL, " ");
          char *task_command = strtok(NULL, "");
          if (time_str && event_str && task_command) {
            time_t scheduled_time = parse_time(time_str);
            if (scheduled_time != -1) {
              schedule_command(task_command, scheduled_time);
            } else {
              printf("Invalid time or event type.\n");
            }
          } else {
            printf("Usage: schedule <time> <event> <command>\n");
          }
        } else if (strncmp(command, "lshedule", 6) == 0) {
          list_scheduled_tasks();
        } else if (strcmp(command, "snapshot") == 0) {
          printf("Snapshotting container...\n");
          char state_file_path[MAX_PATH_LEN];
          time_t now = time(NULL);

          // Construct the state file path using the Unix timestamp
          snprintf(state_file_path, sizeof(state_file_path), "%s/%ld_%s",
                   container_root, now, bin_file_path);

          FILE *state_file = fopen(state_file_path, "wb");
          if (state_file == NULL) {
            perror("Error creating container state file for snapshot");
          } else {
            save_container_state(state_file, &config, &container_state);
            fclose(state_file);
            printf("Container state saved to %s\n", state_file_path);
          }
        } else if (strncmp(command, "secret ", 7) == 0) {
          handle_secret_command(command + 7);
        } else if (strncmp(command, "getsecret ", 10) == 0) {
          handle_getsecret_command(command + 10);
        } else if (strcmp(command, "help") == 0) {
          printf("Commands:\n");
          printf("  exit: Exit the container\n");
          printf("  debug: Enter debug mode\n");
          printf("  scale <memory_soft_limit> <memory_hard_limit> "
                 "<cpu_priority>: Set memory limits and CPU priority\n");
          printf("  xs <script_content>: Execute a script in the container\n");
          printf("  osxs <filename>: Execute a script file in the container\n");
          printf("  autoscale: Start automatic resource scaling\n");
          printf("  status: Print current resource usage\n");
          printf("  br <command>: Start a background task\n");
          printf("  pause: Pause all background tasks\n");
          printf("  unpause: Unpause all background tasks\n");
          printf("  wait <task_id>: Wait for a background task to finish\n");
          printf("  ps: List all background tasks\n");
          printf("  network restart: Restart the network listener\n");
          printf("  network start: Start the network listener\n");
          printf("  network stop: Stop the network listener\n");
          printf("  network status: Check the network listener status\n");
          printf("  trace <command>: Execute a command with system call "
                 "tracing\n");
          printf("  proctrace <process_id>: Trace system calls of a running "
                 "background process\n");
          printf("  attach <task_id>: Attach to a background task\n");
          printf("  schedule <time> <event> <command>: Schedule a command to "
                 "run at a specific time\n");
          printf("  lshedule: List scheduled tasks\n");
          printf(" snapshot: snapshots container");
          printf("  secret <key> <VAR>=<val>: Set an encrypted environment "
                 "variable\n");
          printf("  getsecret <key> <VAR>: Decrypt and print a secret value\n");
          printf("  help: Print this help message\n");
          printf(" stop: Stops the container and saves its state\n");
        } else if (strcmp(command, "stop") == 0) {
          printf("Stopping container and saving state...\n");
          char state_file_path[MAX_PATH_LEN];
          time_t now = time(NULL);

          // Construct the state file path using the Unix timestamp
          snprintf(state_file_path, sizeof(state_file_path), "%s/%ld_%s",
                   container_root, now, bin_file_path);

          FILE *state_file = fopen(state_file_path, "wb");
          if (state_file == NULL) {
            perror("Error creating container state file for stopping");
          } else {
            save_container_state(state_file, &config, &container_state);
            fclose(state_file);
            printf("Container state saved to %s\n", state_file_path);
          }

          goto stop_loop;
        } else {
          execute_command(command, container_root);
        }
        printf("\n");
        add_to_history(command);
        char log_file_path[MAX_PATH_LEN];
        snprintf(log_file_path, sizeof(log_file_path), "%s/var/log/log.txt",
                 container_root);
        FILE *log_file = fopen(log_file_path, "a");
        if (log_file == NULL) {
          perror("Failed to open log file");
        } else {
          fprintf(log_file, "\nCommand History:\n");
          for (int i = 0; i < command_index; i++) {
            fprintf(log_file, "Command %d: %s\n", i + 1, history.commands[i]);
          }
          fclose(log_file);
        }
        command_index = 0;
        cursor_pos = 0;
        set_terminal_raw_mode();
        printf("> ");
        fflush(stdout);
      } else {
        if (command_index < MAX_COMMAND_LEN - 1) {
          memmove(&command[cursor_pos + 1], &command[cursor_pos],
                  command_index - cursor_pos + 1);
          command[cursor_pos] = ch;
          command_index++;
          cursor_pos++;
          printf("%s", &command[cursor_pos - 1]);
          move_cursor_left(command_index - cursor_pos);
        }
      }
    }
  }

exit_loop:
  printf("Container terminated.\n");
  // Clean up the threads
  pthread_cancel(network_thread);
  pthread_join(network_thread, NULL);
  pthread_cancel(logger);
  pthread_join(logger, NULL);
  // Cleanup container state
  for (int i = 0; i < container_state.num_env_vars; i++) {
    free(container_state.environment_variables[i]);
  }
  free(container_state.environment_variables);
  exit(0);

stop_loop:
  set_terminal_canonical_mode();
  printf("Container stopped.\n");
  pthread_cancel(network_thread);
  pthread_join(network_thread, NULL);
  pthread_cancel(logger);
  pthread_join(logger, NULL);
  // Preserve the environment variables
  for (int i = 0; i < container_state.num_env_vars; i++) {
    setenv(container_state.environment_variables[i], NULL, 1);
  }
}

void ocreate_isolated_environment(FILE *bin_file, const char *bin_file_path) {
  signal(SIGTERM, handle_signal);
  signal(SIGINT, handle_signal);
  signal(SIGSEGV, handle_signal);

  // Create dedicated container user
  char container_username[64];
  snprintf(container_username, sizeof(container_username), "container_%d",
           getpid());

  ContainerConfig config;
  fread(&config, sizeof(ContainerConfig), 1, bin_file);
  if (create_container_user(container_username, "/tmp",
                            &config.container_uid) != 0) {
    fprintf(stderr,
            "Failed to create container user, falling back to current user\n");
  }

  int num_files;
  fread(&num_files, sizeof(int), 1, bin_file);

  char shared_folder_path[] = "/Volumes/SharedContainer";
  mkdir(shared_folder_path, 0755);

  char disk_image_path[MAX_PATH_LEN];
  snprintf(disk_image_path, sizeof(disk_image_path),
           "/tmp/container_disk_%d.dmg", getpid());

  // Assign the volume name as the bin_file_path
  char create_disk_command[MAX_COMMAND_LEN];
  struct stat st;
  if (stat(bin_file_path, &st) == -1) {
    perror("stat");
  }

  // Get the size of the file in bytes
  off_t file_size = st.st_size;

  // Convert the size to gigabytes and add 1 GB
  double size_in_gb = (double)file_size / (1024 * 1024 * 1024) + 1.0;

  // Format the size to two decimal places
  snprintf(create_disk_command, sizeof(create_disk_command),
           "hdiutil create -size %.2fg -fs HFS+ -volname \"%s\" %s", size_in_gb,
           bin_file_path, disk_image_path);

  system(create_disk_command);

  chmod(disk_image_path, 0644);

  char mount_command[MAX_COMMAND_LEN];
  snprintf(mount_command, sizeof(mount_command), "hdiutil attach %s",
           disk_image_path);
  system(mount_command);

  // Use bin_file_path as the root volume name
  char container_root[MAX_PATH_LEN];
  snprintf(container_root, sizeof(container_root), "/Volumes/%s",
           bin_file_path);

  char shared_mount_point[MAX_PATH_LEN];
  snprintf(shared_mount_point, sizeof(shared_mount_point), "%s/shared",
           container_root);
  symlink(shared_folder_path, shared_mount_point);

  for (int i = 0; i < num_files; i++) {
    File file;
    fread(file.name, sizeof(char), MAX_PATH_LEN, bin_file);
    fread(&file.size, sizeof(size_t), 1, bin_file);

    file.data = malloc(file.size);
    if (file.data == NULL) {
      perror("Error allocating memory for file data");
      exit(EXIT_FAILURE);
    }

    fread(file.data, 1, file.size, bin_file);

    char file_path[MAX_PATH_LEN];
    snprintf(file_path, sizeof(file_path), "%s/%s", container_root, file.name);

    create_directories(file_path);

    FILE *out_file = fopen(file_path, "wb");
    if (out_file == NULL) {
      perror("Error creating file in container");
      exit(EXIT_FAILURE);
    }

    fwrite(file.data, 1, file.size, out_file);
    fclose(out_file);
    free(file.data);

    chmod(file_path, 0755);
  }

  link_system_directories(container_root);

  chmod(container_root, 0755);

  // Set ownership of container root to the dedicated user
  char chown_command[MAX_COMMAND_LEN];
  snprintf(chown_command, sizeof(chown_command), "chown -R %d:%d %s",
           config.container_uid, config.container_gid, container_root);
  system(chown_command);

  if (launch_container_as_user(container_username, bin_file_path,
                               container_root) != 0) {
    fprintf(stderr, "Failed to launch container as user %s\n",
            container_username);
    exit(1);
  }

  if (chdir(container_root) != 0) {
    perror("Failed to change to container root directory");
    exit(1);
  }

  if (setgid(config.container_gid) != 0) {
    perror("Failed to set group ID");
    exit(1);
  }

  if (setuid(config.container_uid) != 0) {
    perror("Failed to set user ID");
    exit(1);
  }

  create_fake_system_files(container_root);

  apply_resource_limits(&config);

  char sandbox_profile[2048];
  snprintf(sandbox_profile, sizeof(sandbox_profile),
           "(version 1)"
           "(deny default)"
           "(allow process-fork)"
           "(allow file-read*)"
           "(allow file-write* (subpath \"%s\"))"
           "(allow file-read* (subpath \"%s\"))"
           "(allow file-read* (literal \"%s\"))"
           "(allow file-read* (subpath \"/usr\"))"
           "(deny file-read* (subpath \"/usr/local\"))"
           "(allow file-read* (subpath \"/bin\"))"
           "(allow file-read* (subpath \"/sbin\"))"
           "(allow file-read* (subpath \"/dev\"))"
           "(allow file-read* (subpath \"/System\"))"
           "(allow file-read* (subpath \"%s\"))"
           "(allow file-read* (subpath \"/Applications/Xcode.app\"))"
           "(allow file-write* (subpath \"%s\"))"
           "(allow network-outbound (remote ip))"
           "(allow network-inbound (local ip))"
           "(allow process-exec (subpath \"/usr\"))"
           "(deny process-exec (subpath \"/usr/local\"))"
           "(allow process-exec (subpath \"/Applications/Xcode.app\"))"
           "(allow process-exec (subpath \"/bin\"))"
           "(allow process-exec (subpath \"/bin\"))"
           "(allow process-exec (subpath \"/sbin\"))"
           "(allow process-exec (subpath \"/dev\"))"
           "(allow process-exec (subpath \"%s\"))",
           container_root, container_root, bin_file_path, shared_mount_point,
           shared_mount_point, container_root);

  char *error;
  if (sandbox_init(sandbox_profile, 0, &error) != 0) {
    fprintf(stderr, "sandbox_init failed: %s\n", error);
    sandbox_free_error(error);
    exit(1);
  }

  printf("\n=== Container %s Terminal (User: %s) ===\n", bin_file_path,
         container_username);
  printf("Enter commands (type 'exit' to quit, help for help):\n");
  printf("If you just ran the container ignore the first log file error");

  if (config.start_config[0] != '\0') {
    char start_config_path[MAX_PATH_LEN];
    snprintf(start_config_path, sizeof(start_config_path), "%s/%s",
             container_root, config.start_config);
    execute_start_config(start_config_path, container_root);
  }

  char command[MAX_COMMAND_LEN];
  int command_index = 0;
  int cursor_pos = 0;

  set_terminal_raw_mode();

  pthread_t logger;
  pthread_create(&logger, NULL, logger_thread, &config);

  while (1) {
    if (should_exit) {
      break;
    }

    check_scheduled_tasks(container_root);

    printf("> ");
    fflush(stdout);

    int ch;
    while ((ch = getchar()) != EOF) {
      if (ch == 27) {    // ESC key
        getchar();       // Skip the next character
        ch = getchar();  // Get the actual key code
        if (ch == 'A') { // Up arrow
          navigate_history(command, &command_index, &cursor_pos, -1);
        } else if (ch == 'B') { // Down arrow
          navigate_history(command, &command_index, &cursor_pos, 1);
        } else if (ch == 'C') { // Right arrow
          if (cursor_pos < command_index) {
            move_cursor_right(1);
            cursor_pos++;
          }
        } else if (ch == 'D') { // Left arrow
          if (cursor_pos > 0) {
            move_cursor_left(1);
            cursor_pos--;
          }
        }
      } else if (ch == 127 || ch == 8) { // Backspace or Delete
        if (cursor_pos > 0) {
          move_cursor_left(1);
          clear_line();
          memmove(&command[cursor_pos - 1], &command[cursor_pos],
                  command_index - cursor_pos + 1);
          command_index--;
          cursor_pos--;
          printf("%s", &command[cursor_pos]);
          move_cursor_left(command_index - cursor_pos);
        }
      } else if (ch == '\n' || ch == '\r') { // Enter key
        command[command_index] = '\0';
        set_terminal_canonical_mode();
        usleep(10000); // 10ms delay

        if (strcmp(command, "exit") == 0)
          goto exit_loop;
        if (strcmp(command, "debug") == 0) {
          debug_mode = DEBUG_STEP;
          printf("Entered debug mode. Type 'help' for debug commands.\n");
        } else if (strncmp(command, "scale", 5) == 0) {
          long memory_soft_limit, memory_hard_limit;
          int cpu_priority;
          if (sscanf(command, "scale %ld %ld %d", &memory_soft_limit,
                     &memory_hard_limit, &cpu_priority) == 3) {
            scale_container_resources(memory_soft_limit, memory_hard_limit,
                                      cpu_priority);
          } else {
            printf("Usage: scale <memory_soft_limit> <memory_hard_limit> "
                   "<cpu_priority>\n");
          }
        } else if (strncmp(command, "secret ", 7) == 0) {
          handle_secret_command(command + 7);
        } else if (strncmp(command, "getsecret ", 10) == 0) {
          handle_getsecret_command(command + 10);
        } else if (strncmp(command, "xs", 6) == 0) {
          char *script_content = command + 7;
          handle_script_command(script_content);
        } else if (strncmp(command, "osxs", 4) == 0) {
          char *filename = command + 5;
          while (isspace(*filename)) {
            filename++;
          }
          handle_script_file(filename);
        } else if (strcmp(command, "autoscale") == 0) {
          start_auto_scaling(&config);
        } else if (strcmp(command, "status") == 0) {
          print_current_resource_usage(&config);
        } else if (strncmp(command, "br ", 3) ==
                   0) {            // Note the space after 'br'
          char *cmd = command + 3; // Skip "br " prefix
          while (isspace(*cmd))
            cmd++; // Skip any additional whitespace
          if (*cmd) {
            int task_id = start_background_task(cmd, container_root);
            if (task_id >= 0) {
              printf("Started background task %d: %s\n", task_id, cmd);
            } else {
              printf("Failed to start background task\n");
            }
          } else {
            printf("Usage: br <command>\n");
          }
        } else if (strcmp(command, "pause") == 0) {
          pause_background_tasks();
          printf("All background tasks paused\n");
        } else if (strcmp(command, "unpause") == 0) {
          unpause_background_tasks();
          printf("All background tasks unpaused\n");
        } else if (strncmp(command, "wait ", 5) == 0) {
          int task_id;
          if (sscanf(command + 5, "%d", &task_id) == 1) {
            wait_background_task(task_id);
          } else {
            printf("Usage: wait <task_id>\n");
          }
        } else if (strncmp(command, "wait", 4) == 0) {
          int task_id;
          if (sscanf(command + 5, "%d", &task_id) == 1) {
            wait_background_task(task_id);
          } else {
            printf("Usage: wait <task_id>\n");
          }
        } else if (strcmp(command, "ps") == 0) {
          show_background_tasks();
        } else if (strncmp(command, "trace ", 6) == 0) {
          char *cmd = command + 6; // Skip "trace " prefix
          while (isspace(*cmd))
            cmd++; // Skip any additional whitespace
          if (*cmd) {
            trace_command(cmd, container_root);
          } else {
            printf("Usage: trace <command>\n");
          }
        } else if (strncmp(command, "proctrace ", 10) == 0) {
          int process_id;
          if (sscanf(command + 10, "%d", &process_id) == 1) {
            // Pass the background_tasks array and MAX_BACKGROUND_TASKS constant
            trace_background_process(process_id, container_root);
          } else {
            printf("Usage: proctrace <process_id>\n");
          }
        } else if (strcmp(command, "cps") == 0) {
          // Live process inspection - like top/htop
          live_process_inspection(container_root);
        } else if (strncmp(command, "attach ", 7) == 0) {
          int task_id;
          if (sscanf(command + 7, "%d", &task_id) == 1) {
            attach_to_background_task(task_id);
          } else {
            printf("Usage: attach <task_id>\n");
          }
        } else if (strncmp(command, "schedule", 8) == 0) {
          char *cmd = command + 9; // Skip "schedule " prefix
          while (isspace(*cmd))
            cmd++; // Skip any additional whitespace

          char *time_str = strtok(cmd, " ");
          char *event_str = strtok(NULL, " ");
          char *task_command = strtok(NULL, "");

          if (time_str && event_str && task_command) {
            time_t scheduled_time = parse_time(time_str);

            if (scheduled_time != -1) {
              schedule_command(task_command, scheduled_time);
            } else {
              printf("Invalid time or event type.\n");
            }
          } else {
            printf("Usage: schedule <time> <event> <command>\n");
          }
        } else if (strncmp(command, "lshedule", 6) == 0) {
          list_scheduled_tasks();
        } else if (strcmp(command, "snapshot") == 0) {
          printf("Snapshotting container...\n");
          char state_file_path[MAX_PATH_LEN];
          time_t now = time(NULL);

          // Construct the state file path using the Unix timestamp
          snprintf(state_file_path, sizeof(state_file_path), "%s/%ld_%s",
                   container_root, now, bin_file_path);

          FILE *state_file = fopen(state_file_path, "wb");
          if (state_file == NULL) {
            perror("Error creating container state file for snapshot");
          } else {
            save_container_state(state_file, &config, &container_state);
            fclose(state_file);
            printf("Container state saved to %s\n", state_file_path);
          }
        } else if (strncmp(command, "secret ", 7) == 0) {
          handle_secret_command(command + 7);
        } else if (strncmp(command, "getsecret ", 10) == 0) {
          handle_getsecret_command(command + 10);
        } else if (strcmp(command, "help") == 0) {
          printf("Commands:\n");
          printf("  exit: Exit the container\n");
          printf("  debug: Enter debug mode\n");
          printf("  scale <memory_soft_limit> <memory_hard_limit> "
                 "<cpu_priority>: Set memory limits and CPU priority\n");
          printf("  xs <script_content>: Execute a script in the container\n");
          printf("  osxs <filename>: Execute a script file in the container\n");
          printf("  autoscale: Start automatic resource scaling\n");
          printf("  status: Print current resource usage\n");
          printf("  br <command>: Start a background task\n");
          printf("  pause: Pause all background tasks\n");
          printf("  unpause: Unpause all background tasks\n");
          printf("  wait <task_id>: Wait for a background task to finish\n");
          printf("  ps: List all background tasks\n");
          printf("  trace <command>: Execute a command with system call "
                 "tracing\n");
          printf("  proctrace <process_id>: Trace system calls of a running "
                 "background process\n");
          printf("  attach <task_id>: Attach to a background task\n");
          printf("  schedule <time> <event> <command>: Schedule a command to "
                 "run at a specific time\n");
          printf("  lshedule: List scheduled tasks\n");
          printf(" snapshot: Snapshots a container");
          printf("  secret <key> <VAR>=<val>: Set an encrypted environment "
                 "variable\n");
          printf("  getsecret <key> <VAR>: Decrypt and print a secret value\n");
          printf("  help: Print this help message\n");
          printf(" stop: Stops the container and saves its state\n");
        } else if (strcmp(command, "stop") == 0) {
          printf("Stopping container and saving state...\n");
          char state_file_path[MAX_PATH_LEN];
          time_t now = time(NULL);

          // Construct the state file path using the Unix timestamp
          snprintf(state_file_path, sizeof(state_file_path), "%s/%ld_%s",
                   container_root, now, bin_file_path);

          FILE *state_file = fopen(state_file_path, "wb");
          if (state_file == NULL) {
            perror("Error creating container state file for stopping");
          } else {
            save_container_state(state_file, &config, &container_state);
            fclose(state_file);
            printf("Container state saved to %s\n", state_file_path);
          }

          goto stop_loop;
        } else {
          execute_command(command, container_root);
        }

        printf("\n");
        add_to_history(command);
        char log_file_path[MAX_PATH_LEN];
        snprintf(log_file_path, sizeof(log_file_path), "%s/var/log/log.txt",
                 container_root);
        FILE *log_file = fopen(log_file_path, "a");
        if (log_file == NULL) {
          perror("Failed to open log file");
          printf("If you just ran the container ignore this");
        } else {
          fprintf(log_file, "\nCommand History:\n");
          for (int i = 0; i < command_index; i++) {
            fprintf(log_file, "Command %d: %s\n", i + 1, history.commands[i]);
          }
          fclose(log_file);
        }
        command_index = 0;
        cursor_pos = 0;
        set_terminal_raw_mode();
        printf("> ");
        fflush(stdout);
      } else {
        if (command_index < MAX_COMMAND_LEN - 1) {
          memmove(&command[cursor_pos + 1], &command[cursor_pos],
                  command_index - cursor_pos + 1);
          command[cursor_pos] = ch;
          command_index++;
          cursor_pos++;
          printf("%s", &command[cursor_pos - 1]);
          move_cursor_left(command_index - cursor_pos);
        }
      }
    }
  }

exit_loop:
  set_terminal_canonical_mode();
  printf("Container terminated.\n");

  pthread_cancel(logger);
  pthread_join(logger, NULL);

  for (int i = 0; i < container_state.num_env_vars; i++) {
    free(container_state.environment_variables[i]);
  }
  free(container_state.environment_variables);
  exit(0);

stop_loop:
  set_terminal_canonical_mode();
  printf("Container stopped.\n");
  pthread_cancel(logger);
  pthread_join(logger, NULL);

  // Preserve the environment variables
  for (int i = 0; i < container_state.num_env_vars; i++) {
    setenv(container_state.environment_variables[i], NULL, 1);
  }
}

size_t write_data(void *ptr, size_t size, size_t nmemb, FILE *stream) {
  size_t written = fwrite(ptr, size, nmemb, stream);
  return written;
}

void download_file(const char *file_name) {
  CURL *curl;
  FILE *fp;
  CURLcode res;
  curl = curl_easy_init();
  if (curl) {
    char save_path[256];
    snprintf(save_path, sizeof(save_path), "./%s", file_name);
    fp = fopen(save_path, "wb");
    char url[256];
    snprintf(url, sizeof(url),
             "https://bristle-sideways-blob.glitch.me/uploads/%s", file_name);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
    res = curl_easy_perform(curl);
    if (res != CURLE_OK)
      fprintf(stderr, "curl_easy_perform() failed: %s\n",
              curl_easy_strerror(res));
    fclose(fp);
    curl_easy_cleanup(curl);
  }
}

struct Memory {
  char *response;
  size_t size;
};

static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb,
                                  void *userp) {
  size_t realsize = size * nmemb;
  struct Memory *mem = (struct Memory *)userp;

  char *ptr = realloc(mem->response, mem->size + realsize + 1);
  if (ptr == NULL) {
    printf("Not enough memory (realloc returned NULL)\n");
    return 0;
  }

  mem->response = ptr;
  memcpy(&(mem->response[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->response[mem->size] = 0;

  return realsize;
}

void search(const char *term) {
  CURL *curl;
  CURLcode res;
  struct Memory chunk = {0};

  curl_global_init(CURL_GLOBAL_DEFAULT);
  curl = curl_easy_init();

  if (curl) {
    char url[256];
    snprintf(url, sizeof(url),
             "https://osxiec-file-server-1.onrender.com/search?term=%s", term);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

    res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
      fprintf(stderr, "curl_easy_perform() failed: %s\n",
              curl_easy_strerror(res));
    } else {
      printf("Search results:\n%s\n", chunk.response);
    }

    curl_easy_cleanup(curl);
  }

  free(chunk.response);
  curl_global_cleanup();
}

void upload_file(const char *filename, const char *username,
                 const char *password, const char *description) {
  CURL *curl;
  CURLcode res;
  struct curl_httppost *formpost = NULL;
  struct curl_httppost *lastptr = NULL;

  curl_global_init(CURL_GLOBAL_ALL);

  // Create the form
  curl_formadd(&formpost, &lastptr, CURLFORM_COPYNAME, "file", CURLFORM_FILE,
               filename, CURLFORM_END);

  curl_formadd(&formpost, &lastptr, CURLFORM_COPYNAME, "username",
               CURLFORM_COPYCONTENTS, username, CURLFORM_END);

  curl_formadd(&formpost, &lastptr, CURLFORM_COPYNAME, "password",
               CURLFORM_COPYCONTENTS, password, CURLFORM_END);

  curl_formadd(&formpost, &lastptr, CURLFORM_COPYNAME, "description",
               CURLFORM_COPYCONTENTS, description, CURLFORM_END);

  curl = curl_easy_init();
  if (curl) {
    curl_easy_setopt(curl, CURLOPT_URL,
                     "https://osxiec-file-server-1.onrender.com/upload");
    curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost);

    // Perform the request
    res = curl_easy_perform(curl);

    // Check for errors
    if (res != CURLE_OK) {
      fprintf(stderr, "curl_easy_perform() failed: %s\n",
              curl_easy_strerror(res));
    } else {
      printf("File uploaded successfully.\n");
    }

    // Clean up
    curl_easy_cleanup(curl);
  }

  curl_formfree(formpost);
  curl_global_cleanup();
}

void convert_to_docker(const char *osxiec_file, const char *output_dir,
                       const char *base_image, const char *custom_dockerfile) {
  FILE *bin_file = fopen(osxiec_file, "rb");
  if (bin_file == NULL) {
    perror("Error opening osxiec container file");
    return;
  }

  // Read container config
  ContainerConfig config;
  if (fread(&config, sizeof(ContainerConfig), 1, bin_file) != 1) {
    perror("Error reading container config");
    fclose(bin_file);
    return;
  }

  // Create output directory
  if (mkdir(output_dir, 0755) != 0 && errno != EEXIST) {
    perror("Error creating output directory");
    fclose(bin_file);
    return;
  }

  FILE *dockerfile = NULL;
  char dockerfile_path[MAX_PATH_LEN];

  if (custom_dockerfile != NULL) {
    char cmd[MAX_PATH_LEN * 2];
    snprintf(cmd, sizeof(cmd), "cp %s %s/Dockerfile", custom_dockerfile,
             output_dir);
    if (system(cmd) != 0) {
      perror("Error copying custom Dockerfile");
      fclose(bin_file);
      return;
    }
  } else {
    snprintf(dockerfile_path, sizeof(dockerfile_path), "%s/Dockerfile",
             output_dir);
    dockerfile = fopen(dockerfile_path, "w");
    if (dockerfile == NULL) {
      perror("Error creating Dockerfile");
      fclose(bin_file);
      return;
    }

    fprintf(dockerfile, "FROM %s\n\nWORKDIR /app\n\n", base_image);
  }

  // Read number of files
  int num_files;
  if (fread(&num_files, sizeof(int), 1, bin_file) != 1) {
    perror("Error reading number of files");
    if (dockerfile)
      fclose(dockerfile);
    fclose(bin_file);
    return;
  }

  char buffer[CHUNK_SIZE];
  for (int i = 0; i < num_files; i++) {
    char file_name[MAX_PATH_LEN];
    size_t file_size;

    if (fread(file_name, sizeof(char), MAX_PATH_LEN, bin_file) !=
            MAX_PATH_LEN ||
        fread(&file_size, sizeof(size_t), 1, bin_file) != 1) {
      perror("Error reading file metadata");
      if (dockerfile)
        fclose(dockerfile);
      fclose(bin_file);
      return;
    }

    // Create the directory structure
    char *dir_name = dirname(file_name);
    char dir_path[MAX_PATH_LEN];
    snprintf(dir_path, sizeof(dir_path), "%s/%s", output_dir, dir_name);
    if (mkdir(dir_path, 0755) != 0 && errno != EEXIST) {
      perror("Error creating directory");
      continue;
    }

    char file_path[MAX_PATH_LEN];
    snprintf(file_path, sizeof(file_path), "%s/%s", output_dir, file_name);
    FILE *out_file = fopen(file_path, "wb");
    if (out_file == NULL) {
      perror("Error creating file in output directory");
      continue;
    }

    size_t remaining = file_size;
    while (remaining > 0) {
      size_t to_read = (remaining < CHUNK_SIZE) ? remaining : CHUNK_SIZE;
      size_t bytes_read = fread(buffer, 1, to_read, bin_file);
      if (bytes_read == 0) {
        if (feof(bin_file)) {
          fprintf(stderr, "Unexpected end of file\n");
        } else {
          perror("Error reading file data");
        }
        break;
      }
      fwrite(buffer, 1, bytes_read, out_file);
      remaining -= bytes_read;
    }

    fclose(out_file);

    if (custom_dockerfile == NULL) {
      char relative_path[MAX_PATH_LEN];
      snprintf(relative_path, sizeof(relative_path), "%s", file_name);
      fprintf(dockerfile, "COPY %s /app/%s\n", relative_path, relative_path);
    }
  }

  if (custom_dockerfile == NULL) {
    fprintf(dockerfile, "\nENV MEMORY_SOFT_LIMIT=%ld\n",
            config.memory_soft_limit);
    fprintf(dockerfile, "ENV MEMORY_HARD_LIMIT=%ld\n",
            config.memory_hard_limit);
    fprintf(dockerfile, "ENV CPU_PRIORITY=%d\n", config.cpu_priority);

    if (strcmp(config.network_mode, "host") == 0) {
      fprintf(dockerfile, "\n# Using host network mode\n");
    } else if (strcmp(config.network_mode, "bridge") == 0) {
      fprintf(dockerfile, "\n# Using bridge network mode\n");
    }

    if (config.start_config[0] != '\0') {
      fprintf(dockerfile,
              "\nCMD [\"/bin/sh\", \"-c\", \"while read cmd; do $cmd; done < "
              "%s\"]\n",
              config.start_config);
    } else {
      fprintf(dockerfile, "\nCMD [\"/bin/sh\"]\n");
    }

    fclose(dockerfile);
  }

  fclose(bin_file);

  printf("Docker container created in %s\n", output_dir);
  printf("To build: docker build -t {container-name} %s\n", output_dir);
  printf("To run: docker run -it {container-name}\n");
}

void clean_container_dmgs() {
  DIR *dir;
  struct dirent *entry;
  char file_path[MAX_PATH_LEN];

  dir = opendir("/tmp");
  if (dir == NULL) {
    perror("Error opening /tmp directory");
    return;
  }

  while ((entry = readdir(dir)) != NULL) {
    if (strstr(entry->d_name, "container_") && strstr(entry->d_name, ".dmg")) {
      snprintf(file_path, sizeof(file_path), "/tmp/%s", entry->d_name);

      // Remove the file
      if (remove(file_path) == 0) {
        printf("Removed: %s\n", file_path);
      } else {
        perror("Error removing file");
      }
    }
  }

  closedir(dir);
}

void clean_container_plists() {
  DIR *dir;
  struct dirent *entry;
  char file_path[MAX_PATH_LEN];

  dir = opendir("/tmp");
  if (dir == NULL) {
    perror("Error opening /tmp directory");
    return;
  }

  while ((entry = readdir(dir)) != NULL) {
    if (strstr(entry->d_name, "container_") &&
        strstr(entry->d_name, ".plist")) {
      snprintf(file_path, sizeof(file_path), "/tmp/%s", entry->d_name);

      // Remove the file
      if (remove(file_path) == 0) {
        printf("Removed: %s\n", file_path);
      } else {
        perror("Error removing file");
      }
    }
  }

  closedir(dir);
}

void deploy_container(const char *config_file, int deploy_port) {
  FILE *file = fopen(config_file, "r");
  if (file == NULL) {
    perror("Error opening config file");
    return;
  }

  char source_dir[MAX_PATH_LEN] = {0};
  char container_file[MAX_PATH_LEN] = {0};
  char network_name[MAX_PATH_LEN] = {0};
  char start_config[MAX_PATH_LEN] = {0};
  char container_config[MAX_PATH_LEN] = {0};

  char line[MAX_COMMAND_LEN];
  while (fgets(line, sizeof(line), file)) {
    char *key = strtok(line, "=");
    char *value = strtok(NULL, "\n");
    if (key && value) {
      if (strcmp(key, "source_dir") == 0) {
        strncpy(source_dir, value, MAX_PATH_LEN - 1);
      } else if (strcmp(key, "container_file") == 0) {
        strncpy(container_file, value, MAX_PATH_LEN - 1);
      } else if (strcmp(key, "network_name") == 0) {
        strncpy(network_name, value, MAX_PATH_LEN - 1);
      } else if (strcmp(key, "start_config") == 0) {
        strncpy(start_config, value, MAX_PATH_LEN - 1);
      }
    }
  }
  fclose(file);

  if (source_dir[0] == '\0' || container_file[0] == '\0' ||
      network_name[0] == '\0') {
    fprintf(stderr, "Error: Missing required configuration in config file\n");
    return;
  }

  // Contain the directory
  containerize_directory(source_dir, container_file,
                         start_config[0] != '\0' ? start_config : NULL,
                         container_config[0] != '\0' ? container_config : NULL);
  printf("Directory contents containerized into '%s'.\n", container_file);

  // Load network configuration
  ContainerNetwork network = load_container_network(network_name);

  if (network.vlan_id == 0) {
    fprintf(stderr, "Failed to load network configuration for %s\n",
            network_name);
    return;
  }

  if (deploy_port != 0) {
    // Set the global port variable
    port = deploy_port;
  }

  // Run the container
  FILE *bin_file = fopen(container_file, "rb");
  if (bin_file == NULL) {
    perror("Error opening binary file");
    return;
  }
  create_isolated_environment(bin_file, container_file, &network);
  fclose(bin_file);
}

void detach_container_images(const char *volume_name) {
  printf("Detaching %s Containers\n", volume_name);
  char command[MAX_PATH_LEN];
  snprintf(command, sizeof(command), "hdiutil detach -force /Volumes/%s",
           volume_name);
  int result = system(command);
  if (result == 0) {
    printf("Container disk image detached.\n");
  } else {
    fprintf(stderr, "Failed to detach Container disk image.\n");
  }
}

void extract_container(const char *osxiec_file, const char *output_dir) {
  FILE *bin_file = fopen(osxiec_file, "rb");
  if (bin_file == NULL) {
    perror("Error opening osxiec container file");
    return;
  }

  // Read container config
  ContainerConfig config;
  if (fread(&config, sizeof(ContainerConfig), 1, bin_file) != 1) {
    perror("Error reading container config");
    fclose(bin_file);
    return;
  }

  // Create output directory
  if (mkdir(output_dir, 0755) != 0 && errno != EEXIST) {
    perror("Error creating output directory");
    fclose(bin_file);
    return;
  }

  // Read number of files
  int num_files;
  if (fread(&num_files, sizeof(int), 1, bin_file) != 1) {
    perror("Error reading number of files");
    fclose(bin_file);
    return;
  }

  char buffer[CHUNK_SIZE];
  for (int i = 0; i < num_files; i++) {
    char file_name[MAX_PATH_LEN];
    size_t file_size;

    if (fread(file_name, sizeof(char), MAX_PATH_LEN, bin_file) !=
            MAX_PATH_LEN ||
        fread(&file_size, sizeof(size_t), 1, bin_file) != 1) {
      perror("Error reading file metadata");
      fclose(bin_file);
      return;
    }

    // Create the directory structure
    char *dir_name = dirname(file_name);
    char dir_path[MAX_PATH_LEN];
    snprintf(dir_path, sizeof(dir_path), "%s/%s", output_dir, dir_name);
    if (mkdir(dir_path, 0755) != 0 && errno != EEXIST) {
      perror("Error creating directory");
      continue;
    }

    char file_path[MAX_PATH_LEN];
    snprintf(file_path, sizeof(file_path), "%s/%s", output_dir, file_name);
    FILE *out_file = fopen(file_path, "wb");
    if (out_file == NULL) {
      perror("Error creating file in output directory");
      continue;
    }

    size_t remaining = file_size;
    while (remaining > 0) {
      size_t to_read = (remaining < CHUNK_SIZE) ? remaining : CHUNK_SIZE;
      size_t bytes_read = fread(buffer, 1, to_read, bin_file);
      if (bytes_read == 0) {
        if (feof(bin_file)) {
          fprintf(stderr, "Unexpected end of file\n");
        } else {
          perror("Error reading file data");
        }
        break;
      }
      fwrite(buffer, 1, bytes_read, out_file);
      remaining -= bytes_read;
    }

    fclose(out_file);
  }

  fclose(bin_file);

  printf("Container extracted to %s\n", output_dir);
}

typedef enum { ENTRY_FILE, ENTRY_DIR } EntryType;

void create_directory_if_needed(const char *path) {
  char dir[MAX_PATH_LEN];
  snprintf(dir, sizeof(dir), "%s", path);

  for (char *p = dir + 1; *p; p++) {
    if (*p == '/') {
      *p = '\0';
      if (access(dir, F_OK) != 0) { // Check if the directory exists
        if (mkdir(dir, 0777) != 0 && errno != EEXIST) {
          perror("Error creating directory");
          exit(EXIT_FAILURE);
        }
      }
      *p = '/';
    }
  }
  if (access(dir, F_OK) != 0) { // Check if the directory exists
    if (mkdir(dir, 0777) != 0 && errno != EEXIST) {
      perror("Error creating directory");
      exit(EXIT_FAILURE);
    }
  }
}

void convert_to_oci(const char *osxiec_file, const char *output_dir,
                    const char *arch, const char *author, const char *created) {
  if (output_dir == NULL) {
    perror("Output directory is NULL");
    return;
  }

  FILE *bin_file = fopen(osxiec_file, "rb");
  if (bin_file == NULL) {
    perror("Error opening osxiec container file");
    return;
  }

  // Read ContainerConfig
  ContainerConfig config;
  if (fread(&config, sizeof(ContainerConfig), 1, bin_file) != 1) {
    perror("Error reading ContainerConfig");
    fclose(bin_file);
    return;
  }

  // Read number of entries
  int num_entries;
  if (fread(&num_entries, sizeof(int), 1, bin_file) != 1) {
    perror("Error reading number of entries");
    fclose(bin_file);
    return;
  }

  printf("Number of entries: %d\n", num_entries);

  // Create OCI layout file
  char layout_path[MAX_PATH_LEN];
  snprintf(layout_path, sizeof(layout_path), "%s/oci-layout", output_dir);
  FILE *layout_file = fopen(layout_path, "w");
  if (layout_file == NULL) {
    perror("Error creating OCI layout file");
    fclose(bin_file);
    return;
  }
  fprintf(layout_file, "{\"imageLayoutVersion\": \"1.0.0\"}");
  fclose(layout_file);

  // Create blobs directory
  char blobs_dir[MAX_PATH_LEN];
  snprintf(blobs_dir, sizeof(blobs_dir), "%s/blobs/sha256", output_dir);
  create_directory_if_needed(blobs_dir);

  // Prepare config JSON
  json_object *config_json = json_object_new_object();
  json_object_object_add(config_json, "os", json_object_new_string("macOS"));
  json_object_object_add(config_json, "architecture",
                         json_object_new_string(arch));
  json_object_object_add(config_json, "author", json_object_new_string(author));
  json_object_object_add(config_json, "created",
                         json_object_new_string(created));
  json_object_object_add(config_json, "ociVersion",
                         json_object_new_string("1.0.0"));
  json_object_object_add(config_json, "root", json_object_new_object());
  struct json_object *root_object = json_object_new_object();
  struct json_object *path_object = json_object_new_string("");
  json_object_object_add(root_object, "path", path_object);
  json_object_object_add(config_json, "root", root_object);

  // Create config blob
  char config_blob_path[MAX_PATH_LEN];
  snprintf(config_blob_path, sizeof(config_blob_path), "%s/config.json",
           blobs_dir);
  FILE *config_blob = fopen(config_blob_path, "w");
  if (config_blob == NULL) {
    perror("Error creating config blob");
    fclose(bin_file);
    json_object_put(config_json);
    return;
  }
  fprintf(config_blob, "%s",
          json_object_to_json_string_ext(config_json, JSON_C_TO_STRING_PRETTY));
  fclose(config_blob);

  // Prepare manifest JSON
  json_object *manifest_json = json_object_new_object();
  json_object_object_add(manifest_json, "schemaVersion",
                         json_object_new_int(2));
  json_object_object_add(
      manifest_json, "mediaType",
      json_object_new_string("application/vnd.oci.image.manifest.v1+json"));
  json_object_object_add(manifest_json, "config", json_object_new_object());
  json_object_object_add(
      json_object_object_get(manifest_json, "config"), "mediaType",
      json_object_new_string("application/vnd.oci.image.config.v1+json"));
  json_object_object_add(
      json_object_object_get(manifest_json, "config"), "size",
      json_object_new_int64(strlen(json_object_to_json_string(config_json))));
  json_object_object_add(
      json_object_object_get(manifest_json, "config"), "digest",
      json_object_new_string(
          "sha256:configdigest")); // Replace with actual digest

  json_object *layers_array = json_object_new_array();
  json_object_object_add(manifest_json, "layers", layers_array);

  char buffer[CHUNK_SIZE];
  for (int i = 0; i < num_entries; i++) {
    char path[MAX_PATH_LEN];
    if (fread(path, sizeof(char), MAX_PATH_LEN, bin_file) != MAX_PATH_LEN) {
      perror("Error reading entry path");
      fclose(bin_file);
      json_object_put(config_json);
      json_object_put(manifest_json);
      return;
    }

    printf("Entry %d: path=%s\n", i, path);

    // For files
    size_t file_size;
    if (fread(&file_size, sizeof(size_t), 1, bin_file) != 1) {
      perror("Error reading file size");
      fclose(bin_file);
      json_object_put(config_json);
      json_object_put(manifest_json);
      return;
    }

    // Create blob for each file
    char blob_path[MAX_PATH_LEN];
    snprintf(blob_path, sizeof(blob_path), "%s/%s", blobs_dir, path);
    // Ensure the directory exists before creating the file
    char *last_slash = strrchr(blob_path, '/');
    if (last_slash != NULL) {
      *last_slash =
          '\0'; // Temporarily null-terminate the path to create directories
      create_directory_if_needed(blob_path);
      *last_slash = '/'; // Restore the path
    }

    FILE *blob_file = fopen(blob_path, "wb");
    if (blob_file == NULL) {
      perror("Error creating blob file");
      continue;
    }

    size_t remaining = file_size;
    while (remaining > 0) {
      size_t to_read = (remaining < CHUNK_SIZE) ? remaining : CHUNK_SIZE;
      size_t bytes_read = fread(buffer, 1, to_read, bin_file);
      if (bytes_read == 0) {
        if (feof(bin_file)) {
          fprintf(stderr, "Unexpected end of file while reading file data\n");
        } else {
          perror("Error reading file data");
        }
        break;
      }
      fwrite(buffer, 1, bytes_read, blob_file);
      remaining -= bytes_read;
    }
    fclose(blob_file);

    // Add layer to manifest
    json_object *layer = json_object_new_object();
    json_object_object_add(
        layer, "mediaType",
        json_object_new_string("application/vnd.oci.image.layer.v1.tar"));
    json_object_object_add(layer, "size", json_object_new_int64(file_size));
    json_object_object_add(
        layer, "digest",
        json_object_new_string(
            "sha256:layerdigest")); // Replace with actual digest
    json_object_array_add(layers_array, layer);
  }

  // Write manifest
  char manifest_path[MAX_PATH_LEN];
  snprintf(manifest_path, sizeof(manifest_path), "%s/manifest.json",
           output_dir);
  FILE *manifest_file = fopen(manifest_path, "w");
  if (manifest_file == NULL) {
    perror("Error creating manifest file");
    fclose(bin_file);
    json_object_put(config_json);
    json_object_put(manifest_json);
    return;
  }
  fprintf(
      manifest_file, "%s",
      json_object_to_json_string_ext(manifest_json, JSON_C_TO_STRING_PRETTY));
  fclose(manifest_file);

  fclose(bin_file);
  json_object_put(config_json);
  json_object_put(manifest_json);
  printf("OCI container structure created in %s\n", output_dir);
}

char *find_latest_bin_file(const char *volume_name) {
  DIR *dir;
  struct dirent *entry;
  char *latest_file_path = NULL;
  time_t latest_timestamp = 0;
  char search_directory[MAX_PATH_LEN];

  // Format the search directory path
  snprintf(search_directory, sizeof(search_directory), "/Volumes/%s",
           volume_name);

  if ((dir = opendir(search_directory)) == NULL) {
    perror("Unable to open directory");
    return NULL;
  }

  while ((entry = readdir(dir)) != NULL) {
    // Check if the file ends with ".bin"
    if (strstr(entry->d_name, ".bin") != NULL) {
      // Extract Unix timestamp from the beginning of the filename
      time_t timestamp = atol(entry->d_name);

      if (timestamp > latest_timestamp) {
        latest_timestamp = timestamp;

        // Free the previous path and allocate for the new one
        free(latest_file_path);
        latest_file_path = malloc(MAX_PATH_LEN);
        snprintf(latest_file_path, MAX_PATH_LEN, "%s/%s", search_directory,
                 entry->d_name);
      }
    }
  }
  closedir(dir);

  return latest_file_path;
}

int copy_file(const char *source, const char *destination_folder,
              const char *new_file_name) {
  // Construct the full path for the destination file
  char destination[MAX_PATH_LEN];
  snprintf(destination, sizeof(destination), "%s/%s", destination_folder,
           new_file_name);

  FILE *src = fopen(source, "rb");
  if (src == NULL) {
    perror("Error opening source file");
    return -1;
  }

  FILE *dst = fopen(destination, "wb");
  if (dst == NULL) {
    perror("Error opening destination file");
    fclose(src);
    return -1;
  }

  char buffer[BUFSIZ];
  size_t n;
  while ((n = fread(buffer, 1, sizeof(buffer), src)) > 0) {
    if (fwrite(buffer, 1, n, dst) != n) {
      perror("Error writing to destination file");
      fclose(src);
      fclose(dst);
      return -1;
    }
  }

  fclose(src);
  fclose(dst);
  return 0;
}

size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
  size_t total_size = size * nmemb;
  char **response_ptr = (char **)userp;

  // Allocate or reallocate memory for the response
  char *temp =
      realloc(*response_ptr,
              total_size + (*response_ptr ? strlen(*response_ptr) : 0) + 1);
  if (temp == NULL) {
    fprintf(stderr, "Failed to allocate memory.\n");
    return 0; // Abort the transfer
  }
  *response_ptr = temp;

  // Append new data to the response buffer
  if (*response_ptr) {
    memcpy(*response_ptr + (*response_ptr ? strlen(*response_ptr) : 0),
           contents, total_size);
    (*response_ptr)[total_size + (*response_ptr ? strlen(*response_ptr) : 0)] =
        '\0'; // Null-terminate
  }

  return total_size;
}

char *fetch_latest_version(void) {
  CURL *curl;
  CURLcode res;
  char *latest_version = NULL;

  curl = curl_easy_init();
  if (curl) {
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "User-Agent: osxiec-update-checker");

    curl_easy_setopt(
        curl, CURLOPT_URL,
        "https://api.github.com/repos/Okerew/osxiec/releases/latest");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    char *response = NULL;

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    res = curl_easy_perform(curl);

    if (res == CURLE_OK) {
      if (response) {
        struct json_object *parsed_json = json_tokener_parse(response);
        if (parsed_json == NULL) {
          fprintf(stderr, "Failed to parse JSON.\n");
        } else {
          struct json_object *tag_name;
          if (json_object_object_get_ex(parsed_json, "tag_name", &tag_name)) {
            const char *version = json_object_get_string(tag_name);
            latest_version = strdup(version);
          } else {
            fprintf(stderr, "JSON does not contain 'tag_name' field.\n");
          }

          json_object_put(parsed_json);
        }
      } else {
        fprintf(stderr, "No response data received.\n");
      }
    } else {
      fprintf(stderr, "CURL request failed: %s\n", curl_easy_strerror(res));
    }

    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
    free(response);
  } else {
    fprintf(stderr, "Failed to initialize CURL.\n");
  }

  return latest_version;
}

int compare_versions(const char *v1, const char *v2) {
  return strcmp(v1, v2) == 0 ? 0 : -1;
}

int add_plugin(const char *plugin_source) {
  // Get the user's home directory
  const char *home_dir = getenv("HOME");
  if (home_dir == NULL) {
    struct passwd *pwd = getpwuid(getuid());
    if (pwd == NULL) {
      fprintf(stderr, "Unable to determine home directory\n");
      return EXIT_FAILURE;
    }
    home_dir = pwd->pw_dir;
  }

  // Define the plugin directory in the user's home
  char plugin_dir[MAX_PATH_LEN];
  snprintf(plugin_dir, sizeof(plugin_dir), "%s/.osxiec/plugins", home_dir);
  char compile_command[1024];
  char link_command[1024];
  char plugin_name[256];
  char *dot_pos = strrchr(plugin_source, '.');

  if (dot_pos == NULL) {
    fprintf(stderr, "Invalid plugin source file name\n");
    return -1;
  }

  // Extract plugin name without extension
  strncpy(plugin_name, plugin_source, dot_pos - plugin_source);
  plugin_name[dot_pos - plugin_source] = '\0';

  // Compile the plugin as an object file
  snprintf(compile_command, sizeof(compile_command), "gcc -c -fPIC -o %s.o %s",
           plugin_name, plugin_source);

  if (system(compile_command) != 0) {
    fprintf(stderr, "Failed to compile plugin\n");
    return -1;
  }

  // Get the path of the current executable
  char executable_path[PATH_MAX];
  uint32_t size = sizeof(executable_path);
  if (_NSGetExecutablePath(executable_path, &size) != 0) {
    fprintf(stderr, "Failed to get executable path\n");
    return -1;
  }

  // Link the plugin with the main executable
  snprintf(link_command, sizeof(link_command),
           "gcc -dynamiclib -o lib%s.dylib %s.o -undefined dynamic_lookup",
           plugin_name, plugin_name);

  if (system(link_command) != 0) {
    fprintf(stderr, "Failed to create dynamic library from plugin\n");
    return -1;
  }

  // Move the dynamic library to the plugin directory
  char move_command[1024];
  snprintf(move_command, sizeof(move_command), "mv lib%s.dylib %s", plugin_name,
           plugin_dir);

  if (system(move_command) != 0) {
    fprintf(stderr, "Failed to move plugin to plugin directory\n");
    return -1;
  }

  // Clean up the object file
  remove(plugin_name);

  printf("Plugin '%s' has been successfully compiled and moved to the plugin "
         "directory.\n",
         plugin_name);
  printf("To use the plugin, you need to restart the program.\n");

  return 0;
}

int remove_plugin(const char *plugin_name) {
  // Get the user's home directory
  const char *home_dir = getenv("HOME");
  if (home_dir == NULL) {
    struct passwd *pwd = getpwuid(getuid());
    if (pwd == NULL) {
      fprintf(stderr, "Unable to determine home directory\n");
      return EXIT_FAILURE;
    }
    home_dir = pwd->pw_dir;
  }

  // Define the plugin directory in the user's home
  char plugin_dir[MAX_PATH_LEN];
  snprintf(plugin_dir, sizeof(plugin_dir), "%s/.osxiec/plugins", home_dir);

  // Remove the plugin from the plugin directory
  char remove_command[1024];
  snprintf(remove_command, sizeof(remove_command), "rm -f %s/%s.dylib",
           plugin_dir, plugin_name);

  if (system(remove_command) != 0) {
    fprintf(stderr, "Failed to remove plugin\n");
    return -1;
  }

  printf("Plugin '%s' has been successfully removed from the plugin "
         "directory.\n",
         plugin_name);

  return 0;
}

void update_container_config(const char *container_file,
                             const char *new_config_file) {
  // Open the container file in read mode
  FILE *bin_file = fopen(container_file, "rb+");
  if (bin_file == NULL) {
    perror("Error opening container file");
    exit(EXIT_FAILURE);
  }

  // Read the current configuration
  ContainerConfig current_config;
  if (fread(&current_config, sizeof(ContainerConfig), 1, bin_file) != 1) {
    perror("Error reading current configuration");
    fclose(bin_file);
    exit(EXIT_FAILURE);
  }

  // Initialize new configuration with current values
  ContainerConfig new_config = current_config;

  // Read and apply new configuration
  if (new_config_file) {
    read_config_file(new_config_file, &new_config);
  }

  // Seek back to the start of the file
  if (fseek(bin_file, 0, SEEK_SET) != 0) {
    perror("Error seeking to start of file");
    fclose(bin_file);
    exit(EXIT_FAILURE);
  }

  // Write the new configuration
  if (fwrite(&new_config, sizeof(ContainerConfig), 1, bin_file) != 1) {
    perror("Error writing new configuration");
    fclose(bin_file);
    exit(EXIT_FAILURE);
  }

  fclose(bin_file);
  printf("Container configuration updated successfully.\n");
}

int copy_volume_to_directory(const char *volume_name, const char *target_dir) {
  char volume_path[MAX_PATH_LEN];
  snprintf(volume_path, sizeof(volume_path), "/Volumes/%s", volume_name);

  // Check if volume exists
  struct stat st = {0};
  if (stat(volume_path, &st) == -1) {
    fprintf(stderr, "Volume %s does not exist\n", volume_name);
    return EXIT_FAILURE;
  }

  // Create target directory if it doesn't exist
  if (stat(target_dir, &st) == -1) {
    if (mkdir(target_dir, 0755) == -1) {
      fprintf(stderr, "Error creating directory %s: %s\n", target_dir,
              strerror(errno));
      return EXIT_FAILURE;
    }
    printf("Created directory: %s\n", target_dir);
  }

  // Command to copy all files (using cp -R for recursive copy)
  char command[MAX_PATH_LEN * 3];
  snprintf(command, sizeof(command), "cp -R %s/* %s/", volume_path, target_dir);

  int result = system(command);
  if (result == 0) {
    printf("Successfully copied contents from %s to %s\n", volume_path,
           target_dir);
    return EXIT_SUCCESS;
  } else {
    fprintf(stderr, "Failed to copy contents from %s to %s\n", volume_path,
            target_dir);
    return EXIT_FAILURE;
  }
}

void broadcast_command_to_network(const char *network_name, const char *command,
                                  int port) {
  ContainerNetwork network = load_container_network(network_name);
  if (network.vlan_id == 0) {
    fprintf(stderr, "Failed to load network configuration for %s\n",
            network_name);
    return;
  }

  // Set up socket options
  int enable_socket_reuse = 1;
  struct timeval timeout = {.tv_sec = 5, // 5 seconds timeout
                            .tv_usec = 0};

  for (int i = 0; i < network.num_containers; i++) {
    // Create a new socket for each container
    int broadcast_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (broadcast_socket < 0) {
      perror("Socket creation failed");
      continue;
    }

    // Configure socket options
    setsockopt(broadcast_socket, SOL_SOCKET, SO_REUSEADDR, &enable_socket_reuse,
               sizeof(enable_socket_reuse));
    setsockopt(broadcast_socket, SOL_SOCKET, SO_RCVTIMEO, &timeout,
               sizeof(timeout));
    setsockopt(broadcast_socket, SOL_SOCKET, SO_SNDTIMEO, &timeout,
               sizeof(timeout));

    // Set up container address
    struct sockaddr_in container_addr;
    memset(&container_addr, 0, sizeof(container_addr));
    container_addr.sin_family = AF_INET;
    container_addr.sin_port = htons(port); // Using the port parameter

    // Convert IP address string to network format
    if (inet_pton(AF_INET, network.container_ips[i],
                  &container_addr.sin_addr) <= 0) {
      fprintf(stderr, "Invalid container IP address: %s\n",
              network.container_ips[i]);
      close(broadcast_socket);
      continue;
    }

    // Try to connect to the container
    if (connect(broadcast_socket, (struct sockaddr *)&container_addr,
                sizeof(container_addr)) < 0) {
      fprintf(stderr, "Failed to connect to container %s at %s:%d\n",
              network.container_names[i], network.container_ips[i], port);
      close(broadcast_socket);
      continue;
    }

    // Send the command
    ssize_t sent_bytes = send(broadcast_socket, command, strlen(command), 0);
    if (sent_bytes < 0) {
      fprintf(stderr, "Failed to send command to container %s\n",
              network.container_names[i]);
    } else {
      printf("Command sent to container %s at %s:%d (%zd bytes)\n",
             network.container_names[i], network.container_ips[i], port,
             sent_bytes);

      // Wait for response
      char response[1024] = {0};
      ssize_t received_bytes =
          recv(broadcast_socket, response, sizeof(response) - 1, 0);
      if (received_bytes > 0) {
        printf("Response from %s (%zd bytes): %s", network.container_names[i],
               received_bytes, response);
      } else if (received_bytes == 0) {
        printf("Connection closed by container %s\n",
               network.container_names[i]);
      } else {
        perror("Error receiving response");
      }
    }

    close(broadcast_socket);
  }
}

void remove_pf_configs(int vlan_number) {
  const char *base_path = "/etc/";
  char pf_conf_path[256];
  char vlan_conf_path[256];

  // Compose file paths
  snprintf(pf_conf_path, sizeof(pf_conf_path), "%spf.conf", base_path);
  snprintf(vlan_conf_path, sizeof(vlan_conf_path), "%spf.vlan%d.conf",
           base_path, vlan_number);

  // Attempt to remove /etc/pf.conf
  if (remove(pf_conf_path) == 0) {
    printf("Removed: %s\n", pf_conf_path);
  } else {
    perror("Error removing pf.conf");
  }

  // Attempt to remove /etc/pf.vlan{n}.conf
  if (remove(vlan_conf_path) == 0) {
    printf("Removed: %s\n", vlan_conf_path);
  } else {
    perror("Error removing pf.vlanX.conf");
  }
}

void cleanup_all_container_users(void) {
  FILE *fp;
  char line[256];
  char command[512];

  // List all users and filter those starting with 'container_'
  fp = popen("dscl . -list /Users | grep '^container_'", "r");
  if (fp == NULL) {
    perror("Failed to run dscl command");
    return;
  }

  while (fgets(line, sizeof(line), fp) != NULL) {
    // Remove trailing newline
    line[strcspn(line, "\n")] = 0;

    // Build dscl delete command
    snprintf(command, sizeof(command), "dscl . -delete /Users/%s", line);

    printf("Deleting user record for: %s\n", line);
    int ret = system(command);
    if (ret != 0) {
      fprintf(stderr, "Failed to delete user %s\n", line);
    }
  }

  pclose(fp);
  printf("Done cleaning up all container_ users.\n");
}

int main(int argc, char *argv[]) {
  PluginManager plugin_manager;
  plugin_manager_init(&plugin_manager);

  // Get the user's home directory
  const char *home_dir = getenv("HOME");
  if (home_dir == NULL) {
    struct passwd *pwd = getpwuid(getuid());
    if (pwd == NULL) {
      fprintf(stderr, "Unable to determine home directory\n");
      return EXIT_FAILURE;
    }
    home_dir = pwd->pw_dir;
  }

  // Define the plugin directory in the user's home
  char plugin_dir[MAX_PATH_LEN];
  snprintf(plugin_dir, sizeof(plugin_dir), "%s/.osxiec/plugins", home_dir);

  // Check if the directory exists, if not, create it
  struct stat st = {0};
  if (stat(plugin_dir, &st) == -1) {
    // Create the .osxiec directory first
    char osxiec_dir[MAX_PATH_LEN];
    snprintf(osxiec_dir, sizeof(osxiec_dir), "%s/.osxiec", home_dir);
    if (mkdir(osxiec_dir, 0755) == -1 && errno != EEXIST) {
      fprintf(stderr, "Error creating .osxiec directory: %s\n",
              strerror(errno));
      // Continue execution, as the program can still function without plugins
    }

    // Now create the plugins directory
    if (mkdir(plugin_dir, 0755) == -1) {
      fprintf(stderr, "Error creating plugin directory %s: %s\n", plugin_dir,
              strerror(errno));
      // Continue execution, as the program can still function without plugins
    } else {
      printf("Created plugin directory: %s\n", plugin_dir);
    }
  }

  // Load plugins from the directory
  DIR *dir = opendir(plugin_dir);
  if (dir) {
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
      if (entry->d_type == DT_REG) { // Regular file
        char plugin_path[MAX_PATH_LEN];
        snprintf(plugin_path, sizeof(plugin_path), "%s/%s", plugin_dir,
                 entry->d_name);
        plugin_manager_load(&plugin_manager, plugin_path);
      }
    }
    closedir(dir);
  }
  if (argc < 2) {
    fprintf(stderr, "Unknown command: %s\n", argv[0]);
    return EXIT_FAILURE;
  }

  if (strcmp(argv[1], "-contain") == 0) {
    if (argc < 4) {
      fprintf(stderr,
              "Usage for containerize: %s -contain <directory_path> "
              "<output_file> [start_config_file] [container_config_file]\n",
              argv[0]);
      return EXIT_FAILURE;
    }
    if (geteuid() != 0) {
      fprintf(stderr, "This program must be run as root. Try using sudo.\n");
      return EXIT_FAILURE;
    }

    const char *start_config_file = (argc > 4) ? argv[4] : NULL;
    const char *container_config_file = (argc > 5) ? argv[5] : NULL;
    containerize_directory(argv[2], argv[3], start_config_file,
                           container_config_file);
    printf("Directory contents containerized into '%s'.\n", argv[3]);
  } else if (strcmp(argv[1], "-craft") == 0) {
    if (argc < 5) {
      fprintf(stderr,
              "Usage for craft: %s -craft <directory_path> <input_bin_file> "
              "<output_file> <start_config_file> <container_config_file>\n",
              argv[0]);
      return EXIT_FAILURE;
    }
    if (geteuid() != 0) {
      fprintf(stderr, "This program must be run as root. Try using sudo.\n");
      return EXIT_FAILURE;
    }
    if (geteuid() != 0) {
      fprintf(stderr, "This program must be run as root. Try using sudo.\n");
      return EXIT_FAILURE;
    }

    const char *start_config_file = (argc > 5) ? argv[5] : NULL;
    const char *container_config_file = (argc > 6) ? argv[6] : NULL;
    containerize_directory_with_bin_file(
        argv[2], argv[3], argv[4], start_config_file, container_config_file);
    printf("Directory contents containerized into '%s'.\n", argv[4]);
  } else if (strcmp(argv[1], "-network") == 0) {
    if (argc < 4) {
      fprintf(stderr, "Usage: %s -network <create|remove> <name> [vlan_id]\n",
              argv[0]);
      return EXIT_FAILURE;
    }
    if (geteuid() != 0) {
      fprintf(stderr, "This program must be run as root. Try using sudo.\n");
      return EXIT_FAILURE;
    }

    if (strcmp(argv[2], "create") == 0) {
      if (argc < 5) {
        fprintf(stderr,
                "Usage: %s -network create <name> <vlan_id> [allowed_ip]\n",
                argv[0]);
        return EXIT_FAILURE;
      }

      // Check if optional allowed_ip parameter was provided
      const char *allowed_ip = NULL;
      if (argc > 5) {
        allowed_ip = argv[5];
      }

      create_and_save_container_network(argv[3], atoi(argv[4]), allowed_ip);
      ContainerNetwork network = load_container_network(argv[3]);
      setup_pf_rules(&network);
    } else if (strcmp(argv[2], "remove") == 0) {
      if (argc < 4) {
        fprintf(stderr, "Usage: %s -network remove <name>\n", argv[0]);
        return EXIT_FAILURE;
      }
      remove_container_network(argv[3]);
    } else {
      fprintf(stderr, "Unknown network command: %s\n", argv[2]);
      return EXIT_FAILURE;
    }
  } else if (strcmp(argv[1], "-run") == 0) {
    if (argc < 4) {
      fprintf(stderr,
              "Usage: %s -run <container_file> <network_name> [-port <port>]\n",
              argv[0]);
      return EXIT_FAILURE;
    }
    if (geteuid() != 0) {
      fprintf(stderr, "This program must be run as root. Try using sudo.\n");
      return EXIT_FAILURE;
    }

    for (int i = 4; i < argc; i++) {
      if (strcmp(argv[i], "-port") == 0 && i + 1 < argc) {
        port = atoi(argv[i + 1]);
        break;
      }
    }

    // Load network configuration
    ContainerNetwork network = load_container_network(argv[3]);

    if (network.vlan_id == 0) {
      fprintf(stderr, "Failed to load network configuration for %s\n", argv[3]);
      return EXIT_FAILURE;
    }

    FILE *bin_file = fopen(argv[2], "rb");
    if (bin_file == NULL) {
      perror("Error opening binary file");
      return EXIT_FAILURE;
    }
    create_isolated_environment(bin_file, argv[2], &network);
    fclose(bin_file);
  } else if (strcmp(argv[1], "-oexec") == 0) {
    if (argc < 3) {
      fprintf(stderr, "Usage for oexec: %s -oexec <bin_file>\n", argv[0]);
      return EXIT_FAILURE;
    }
    if (geteuid() != 0) {
      fprintf(stderr, "This program must be run as root. Try using sudo.\n");
      return EXIT_FAILURE;
    }

    FILE *bin_file = fopen(argv[2], "rb");
    if (bin_file == NULL) {
      perror("Error opening binary file");
      return EXIT_FAILURE;
    }

    ocreate_isolated_environment(bin_file, argv[2]);
    fclose(bin_file);
  } else if (strcmp(argv[1], "-start") == 0) {
    if (argc < 4) {
      fprintf(stderr,
              "Usage: %s -start <volume_name> <network_name> [-port <port>]\n",
              argv[0]);
      return EXIT_FAILURE;
    }
    if (geteuid() != 0) {
      fprintf(stderr, "This program must be run as root. Try using sudo.\n");
      return EXIT_FAILURE;
    }

    for (int i = 4; i < argc; i++) {
      if (strcmp(argv[i], "-port") == 0 && i + 1 < argc) {
        port = atoi(argv[i + 1]);
        break;
      }
    }

    // Load network configuration
    ContainerNetwork network = load_container_network(argv[3]);

    if (network.vlan_id == 0) {
      fprintf(stderr, "Failed to load network configuration for %s\n", argv[3]);
      return EXIT_FAILURE;
    }

    // Find the latest binary file in the specified volume
    const char *volume_name = argv[2];
    char *latest_bin_file_path = find_latest_bin_file(volume_name);

    if (latest_bin_file_path == NULL) {
      fprintf(stderr, "No valid .bin file found for volume %s\n", volume_name);
      return EXIT_FAILURE;
    }

    // Copy the latest file to the root of the volume with just the volume
    // name
    char dest_folder[MAX_PATH_LEN];
    snprintf(dest_folder, sizeof(dest_folder), "/Volumes/%s", volume_name);

    if (copy_file(latest_bin_file_path, dest_folder, volume_name) != 0) {
      fprintf(stderr, "Failed to copy binary file to volume root\n");
      free(latest_bin_file_path);
      return EXIT_FAILURE;
    }

    // Open the copied binary file
    char full_dest_path[MAX_PATH_LEN];
    snprintf(full_dest_path, sizeof(full_dest_path), "%s/%s", dest_folder,
             volume_name);

    printf("Opening binary file: %s\n", full_dest_path);
    FILE *bin_file = fopen(full_dest_path, "rb");
    if (bin_file == NULL) {
      perror("Error opening binary file");
      fprintf(stderr, "Failed to open: %s\n", full_dest_path);
      free(latest_bin_file_path);
      return EXIT_FAILURE;
    }

    create_isolated_environment(bin_file, volume_name, &network);

    fclose(bin_file);
    free(latest_bin_file_path);
  } else if (strcmp(argv[1], "-pull") == 0) {
    if (argc != 3) {
      printf("Usage: %s -pull <file_name>\n", argv[0]);
      return 1;
    }
    download_file(argv[2]);

  } else if (strcmp(argv[1], "-search") == 0) {
    if (argc != 3) {
      fprintf(stderr, "Usage: %s -search <search_term>\n", argv[0]);
      return EXIT_FAILURE;
    }
    search(argv[2]);
  } else if (strcmp(argv[1], "-upload") == 0) {
    if (argc != 6) {
      fprintf(stderr,
              "Usage: %s -upload <filename> <username> <password> "
              "<description>\n",
              argv[0]);
      return EXIT_FAILURE;
    }
    upload_file(argv[2], argv[3], argv[4], argv[5]);
  } else if (strcmp(argv[1], "-ostart") == 0) {
    if (argc < 2) {
      fprintf(stderr, "Usage: %s -ostart <volume_name>\n", argv[0]);
      return EXIT_FAILURE;
    }
    if (geteuid() != 0) {
      fprintf(stderr, "This program must be run as root. Try using sudo.\n");
      return EXIT_FAILURE;
    }

    // Find the latest binary file in the specified volume
    const char *volume_name = argv[2];
    char *latest_bin_file_path = find_latest_bin_file(volume_name);

    if (latest_bin_file_path == NULL) {
      fprintf(stderr, "No valid .bin file found for volume %s\n", volume_name);
      return EXIT_FAILURE;
    }

    // Copy the latest file to the root of the volume with just the volume name
    char dest_folder[MAX_PATH_LEN];
    snprintf(dest_folder, sizeof(dest_folder), "/Volumes/%s", volume_name);

    if (copy_file(latest_bin_file_path, dest_folder, volume_name) != 0) {
      fprintf(stderr, "Failed to copy binary file to volume root\n");
      free(latest_bin_file_path);
      return EXIT_FAILURE;
    }

    // Open the copied binary file
    char full_dest_path[MAX_PATH_LEN];
    snprintf(full_dest_path, sizeof(full_dest_path), "%s/%s", dest_folder,
             volume_name);

    printf("Opening binary file: %s\n", full_dest_path);
    FILE *bin_file = fopen(full_dest_path, "rb");
    if (bin_file == NULL) {
      perror("Error opening binary file");
      fprintf(stderr, "Failed to open: %s\n", full_dest_path);
      free(latest_bin_file_path);
      return EXIT_FAILURE;
    }

    ocreate_isolated_environment(bin_file, volume_name);

    fclose(bin_file);
    free(latest_bin_file_path);
  } else if (strcmp(argv[1], "-convert-to-docker") == 0) {
    if (argc < 5 || argc > 6) {
      fprintf(stderr,
              "Usage: %s -convert-to-docker <bin_file> <output_directory> "
              "<base_image> [custom_dockerfile]\n",
              argv[0]);
      return EXIT_FAILURE;
    }
    const char *custom_dockerfile = (argc == 6) ? argv[5] : NULL;
    convert_to_docker(argv[2], argv[3], argv[4], custom_dockerfile);
  } else if (strcmp(argv[1], "-convert-to-oci") == 0) {
    if (argc < 6 || argc > 7) {
      fprintf(stderr,
              "Usage: %s -convert-to-oci <bin_file> <output_directory> <arch> "
              "<author> <date>\n",
              argv[0]);
      return EXIT_FAILURE;
    }
    convert_to_oci(argv[2], argv[3], argv[4], argv[5], argv[6]);
  } else if (strcmp(argv[1], "-deploy") == 0) {
    if (argc < 3) {
      fprintf(stderr, "Usage: %s -deploy <config_file> [-port <port>]\n",
              argv[0]);
      return EXIT_FAILURE;
    }
    if (geteuid() != 0) {
      fprintf(stderr, "This program must be run as root. Try using sudo.\n");
      return EXIT_FAILURE;
    }
    int deploy_port = 0;
    for (int i = 3; i < argc; i++) {
      if (strcmp(argv[i], "-port") == 0 && i + 1 < argc) {
        deploy_port = atoi(argv[i + 1]);
        break;
      }
    }
    deploy_container(argv[2], deploy_port);
  } else if (strcmp(argv[1], "-clean") == 0) {
    cleanup_all_container_users();
    clean_container_plists();
    clean_container_dmgs();
    printf(
        "Cleaned up container disk images and plists from /tmp directory.\n");
  } else if (strcmp(argv[1], "-pfclean") == 0) {
    int vlan_number = atoi(argv[2]);

    if (vlan_number < 0) {
      fprintf(stderr, "Invalid VLAN number: %s\n", argv[2]);
      return 1;
    }

    remove_pf_configs(vlan_number);
  } else if (strcmp(argv[1], "-scan") == 0) {
    if (argc != 3) {
      fprintf(stderr, "Usage: %s -scan <bin_file>\n", argv[0]);
      return EXIT_FAILURE;
    }
    security_scan(argv[2]);
  } else if (strcmp(argv[1], "-deploym") == 0) {
    char command[100] = "osxiec_deploy_multiple.sh";

    if (argc > 2) {
      for (int i = 2; i < argc; i++) {
        strcat(command, " ");
        strcat(command, argv[i]);
      }
    }

    system(command);
  } else if (strcmp(argv[1], "-detach") == 0) {
    if (argc != 3) {
      fprintf(stderr, "Usage: %s -detach <volume_name>\n", argv[0]);
      return EXIT_FAILURE;
    }
    detach_container_images(argv[2]);
  } else if (strcmp(argv[1], "-extract") == 0) {
    if (argc != 4) {
      fprintf(stderr,
              "Usage: %s -extract <container_file> <output_directory>\n",
              argv[0]);
      return EXIT_FAILURE;
    }
    extract_container(argv[2], argv[3]);
  } else if (strcmp(argv[1], "-add_plugin") == 0) {
    if (argc != 3) {
      fprintf(stderr, "Usage: %s -add_plugin <plugin_source_file>\n", argv[0]);
      return EXIT_FAILURE;
    }
    if (geteuid() != 0) {
      fprintf(stderr, "This program must be run as root. Try using sudo.\n");
      return EXIT_FAILURE;
    }

    const char *plugin_source = argv[2];
    if (add_plugin(plugin_source) != 0) {
      fprintf(stderr, "Failed to add plugin: %s\n", plugin_source);
      return EXIT_FAILURE;
    }
    printf("Plugin added successfully. Please restart the program.\n");
    return EXIT_SUCCESS; // Exit after adding plugin
  } else if (strcmp(argv[1], "-remove_plugin") == 0) {
    if (argc != 3) {
      fprintf(stderr, "Usage: %s -remove_plugin <plugin_name>\n", argv[0]);
      return EXIT_FAILURE;
    }
    if (geteuid() != 0) {
      fprintf(stderr, "This program must be run as root. Try using sudo.\n");
      return EXIT_FAILURE;
    }

    const char *plugin_name = argv[2];
    if (remove_plugin(plugin_name) != 0) {
      fprintf(stderr, "Failed to remove plugin: %s\n", plugin_name);
      return EXIT_FAILURE;
    }
    printf("Plugin removed successfully. Please restart the program.\n");
    return EXIT_SUCCESS; // Exit after removing plugin
  } else if (strcmp(argv[1], "-bcn") == 0) {
    // broadcast_command_to_network
    if (argc != 5) {
      fprintf(stderr, "Usage: %s -bcn <network_name>, <command>, PORT\n",
              argv[0]);
      return EXIT_FAILURE;
    }
    broadcast_command_to_network(argv[2], argv[3], atoi(argv[4]));
  } else if (strcmp(argv[1], "-help") == 0) {
    printf("Available commands:\n");
    printf("  -contain <directory_path> <output_file> "
           "<path_to_start_config_file> <path_to_container_config_file>\n");
    printf("Contains a directory into a container file\n");
    printf(" -craft <directory_path> <input_bin_file> <output_file> "
           "<path_to_start_config_file> <path_to_container_config_file>\n");
    printf("Crafts a container file from a directory and a bin file\n");
    printf(" -start <container_file> <network_name>\n");
    printf("Starts a stopped container");
    printf(" -ostart <container_file>\n");
    printf("Starts a stopped container in offline mode");
    printf("  -network <create|remove> <name> [vlan_id>\n");
    printf("Manages the vlan network\n");
    printf("  -run <container_file> <network_name> [-port <port>]\n");
    printf("Runs a container file\n");
    printf(" -oexec <container_file>\n");
    printf("Executes a container file in offline mode\n");
    printf("  -pull <file_name>\n");
    printf("Pulls a container from Osxiec Hub\n");
    printf("  -search <search_term>\n");
    printf("Searches for a container in Osxiec Hub\n");
    printf("  -upload <filename> <username> <password> <description>\n");
    printf("Uploads a file to Osxiec Hub\n");
    printf("  -convert-to-docker <bin_file> <output_directory> <base_image> "
           "[custom_dockerfile]\n");
    printf("Converts a binary file to a docker image\n");
    printf("  -convert-to-oci <bin_file> <output_directory> <arch> <author> "
           "<date>\n");
    printf("Converts a binary file to an oci image\n");
    printf("  -clean\n");
    printf("Cleans up container disk images from /tmp directory.\n");
    printf("  -deploy <config_file> [-port <port>]\n");
    printf("Deploys a container from a config file\n");
    printf("  -scan <bin_file>\n");
    printf("Scans a binary file for vulnerabilities\n");
    printf("  -deploym\n");
    printf("Deploys multiple containers from a config file\n");
    printf("  -detach\n");
    printf("Detaches container from /Volumes\n");
    printf("  -extract <container_file> <output_directory>\n");
    printf("Extracts a container file\n");
    printf("  -help\n");
    printf("Prints this help message\n");
    printf("  --version\n");
    printf("Checks for updates and the current version\n");
    printf("  -check_for_update\n");
    printf("Checks for updates and updates the current version\n");
    printf("  -add_plugin <plugin_source_file>\n");
    printf("Adds a plugin\n");
    printf("  -remove_plugin <plugin_name>\n");
    printf("Removes a plugin\n");
    printf("  -update <container_file> <new_config_file>\n");
    printf("Updates a container file with a new config\n");
    printf("  -copy-volume <volume_name> <target_directory>\n");
    printf("Copies volume files to a directory\n");
    printf(" -bcn <network_name>, <command>, PORT\n");
    printf("Broadcasts a command to a network\n");
    printf(" -pfclean VLAN_ID\n");
    printf("Cleans the pf.config files");
  } else if (argc > 1 && strcmp(argv[1], "--version") == 0) {
    char *latest_version = fetch_latest_version();
    if (latest_version) {
      int comparison = compare_versions(VERSION, latest_version);
      if (comparison < 0) {
        printf("An update is available. Latest version: %s\n", latest_version);
        printf("Your current version: %s\n", VERSION);
        printf("Please visit https://github.com/Okerew/osxiec/releases/latest "
               "to update.\n");
      } else if (comparison == 0) {
        printf("You are running the latest version (%s).\n", VERSION);
      } else {
        printf("Your version (%s) is newer than the latest known version "
               "(%s).\n",
               VERSION, latest_version);
      }
      free(latest_version);
    } else {
      printf("Failed to check for updates. Please check your internet "
             "connection.\n");
      printf("Your current version: %s\n", VERSION);
    }
  } else if (strcmp(argv[1], "-update") == 0) {
    if (argc != 4) {
      fprintf(stderr, "Usage: %s -update<container_file> <new_config_file>\n",
              argv[0]);
      return EXIT_FAILURE;
    }
    if (geteuid() != 0) {
      fprintf(stderr, "This program must be run as root. Try using sudo.\n");
      return EXIT_FAILURE;
    }
    update_container_config(argv[2], argv[3]);
  } else if (strcmp(argv[1], "-copy-volume") == 0) {
    if (argc != 4) {
      fprintf(stderr,
              "Usage: %s -copy-volume <volume_name> <target_directory>\n",
              argv[0]);
      return EXIT_FAILURE;
    }
    return copy_volume_to_directory(argv[2], argv[3]);
  } else if (strcmp(argv[1], "-check_for_update") == 0) {
    char *latest_version = fetch_latest_version();
    if (latest_version) {
      int comparison = compare_versions(VERSION, latest_version);
      if (comparison < 0) {
        printf("An update is available. Latest version: %s\n", latest_version);
        printf("Your current version: %s\n", VERSION);
        if (strcmp(OSXIEC_ARCHITECTURE, "arm64") == 0) {
          char update_command[MAX_COMMAND_LEN];
          sprintf(update_command,
                  "curl -L -o osxiec_cli.tar.gz "
                  "https://github.com/Okerew/osxiec/releases/download/%s/"
                  "osxiec_cli.tar.gz",
                  latest_version);
          system(update_command);
          system("tar -xvzf osxiec_cli.tar.gz");
          const char *path = "osxiec_cli";

          if (chdir(path) != 0) {
            perror("chdir() to 'osxiec_cli' failed");
            return 1;
          }

          system("sudo sh install.sh");
        }
        if (strcmp(OSXIEC_ARCHITECTURE, "86_64") == 0) {
          char update_command[MAX_COMMAND_LEN];
          sprintf(update_command,
                  "curl -L -o osxiec_cli_86_64.tar.gz "
                  "https://github.com/Okerew/osxiec/releases/download/%s/"
                  "osxiec_cli.tar.gz",
                  latest_version);
          system(update_command);
          system("tar -xvzf osxiec_cli_86_64.tar.gz");
          const char *path = "osxiec_cli_86_64";

          if (chdir(path) != 0) {
            perror("chdir() to 'osxiec_cli' failed");
            return 1;
          }

          system("sudo sh install.sh");
        } else {
          printf("There was some error while updating. Please visit "
                 "https://github.com/Okerew/osxiec/releases/latest to "
                 "update.\n");
        }
      } else if (comparison == 0) {
        printf("You are running the latest version (%s).\n", VERSION);
      }
      free(latest_version);
    } else {
      printf("Failed to check for updates. Please check your internet "
             "connection.\n");
      printf("Your current version: %s\n", VERSION);
    }
  } else if (strcmp(argv[1], "-api") == 0) {
    if (strcmp(argv[2], "execute_command") == 0) {
      execute_command(argv[3], NULL);
    } else if (strcmp(argv[2], "copy_file") == 0) {
      copy_file(argv[3], argv[4], argv[5]);
    } else if (strcmp(argv[2], "execute_script_file") == 0) {
      execute_script_file(argv[3]);
    } else if (strcmp(argv[2], "get_ip_address") == 0) {
      char *ip_address = get_ip_address();
      printf("%s\n", ip_address);
    } else if (strcmp(argv[2], "isbase64") == 0) {
      int value_is_base64 = is_base64(argv[3]);
      printf("%d\n", value_is_base64);
    } else if (strcmp(argv[2], "find_latest_bin_file") == 0) {
      char *latest_bin_file = find_latest_bin_file(argv[3]);
      printf("%s\n", latest_bin_file);
    } else if (strcmp(argv[2], "create_directories") == 0) {
      create_directories(argv[3]);
    } else if (strcmp(argv[2], "execute_start_config") == 0) {
      execute_start_config(argv[3], argv[4]);
    } else if (strcmp(argv[2], "start_network_listener") == 0) {
      start_network_listener(argv[1]);
    } else {
      printf("This feature is not accessible in the api\n");
    }
  } else {
    fprintf(stderr, "Unknown command: %s\n", argv[1]);
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
