#include "globals/globals.h"
#include "log/log.h"
#include "osxiec.h"
#include <curl/curl.h>
#include <dirent.h>
#include <errno.h>
#include <json-c/json.h>
#include <mach-o/dyld.h>
#include <mach/mach.h>
#include <pthread.h>
#include <pwd.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

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

  container_log(LOG_INFO, "state",
                "cwd=%s last_cmd=\"%s\" procs=%d network=%s env_vars=%d",
                container_state.current_directory,
                container_state.last_executed_command,
                container_state.num_processes, container_state.network_status,
                container_state.num_env_vars);
}

// Handle one command typed at the "debug>" prompt. Returns 1 when execution
// should resume (the prompt loop exits), 0 to keep prompting.
int handle_debug_command(char *command) {
  if (strcmp(command, "continue") == 0 || strcmp(command, "c") == 0) {
    // Resume execution. With no breakpoint armed there is nothing left to
    // pause on, so single-stepping is turned off entirely.
    if (debug_mode != DEBUG_BREAK)
      debug_mode = DEBUG_NONE;
    return 1;
  } else if (strcmp(command, "step") == 0 || strcmp(command, "s") == 0) {
    // Run the next command, then pause again.
    debug_mode = DEBUG_STEP;
    return 1;
  } else if (strncmp(command, "break ", 6) == 0) {
    if (breakpoint)
      free(breakpoint);
    breakpoint = strdup(command + 6);
    debug_mode = DEBUG_BREAK;
    printf("Breakpoint set: pausing on commands containing '%s'\n", breakpoint);
    return 0;
  } else if (strcmp(command, "print") == 0 || strcmp(command, "p") == 0) {
    print_container_state();
    return 0;
  } else if (strncmp(command, "print ", 6) == 0 ||
             strncmp(command, "p ", 2) == 0) {
    char *var_name = command + (command[1] == ' ' ? 2 : 6);
    char *var_value = getenv(var_name);
    if (var_value) {
      printf("%s = %s\n", var_name, var_value);
    } else {
      printf("Variable %s not found\n", var_name);
    }
    return 0;
  } else if (strcmp(command, "help") == 0 || strcmp(command, "h") == 0) {
    printf("Debug commands:\n");
    printf("  continue (c) - Resume execution\n");
    printf("  step (s) - Execute the next command, then pause again\n");
    printf("  break <command> - Pause when a command contains <command>\n");
    printf("  print (p) - Print container state\n");
    printf("  print <var> (p <var>) - Print value of environment variable\n");
    printf("  help (h) - Show this help message\n");
    return 0;
  } else {
    printf("Unknown debug command. Type 'help' for a list of commands.\n");
    return 0;
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

    container_log(LOG_INFO, "stats",
                  "cpu=%.2f%% mem=%ld/%ld bytes (%.2f%%) cpu_prio=%d",
                  cpu_usage, memory_used, config->memory_soft_limit,
                  memory_usage_percent, config->cpu_priority);
  } else {
    perror("Failed to get resource usage");
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
