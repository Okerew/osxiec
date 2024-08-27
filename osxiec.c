#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <sandbox.h>
#include <mach/mach.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <spawn.h>
#include <curl/curl.h>
#include <readline/readline.h>
#include "plugin_manager/plugin_manager.h"
#include <pwd.h>
#include <regex.h>
#include <stdbool.h>
#include "osxiec_script/osxiec_script.h"
#include <libgen.h>
#include "/usr/local/Cellar/json-c/0.17/include/json-c/json.h"
#include <termios.h>

#define MAX_COMMAND_LEN 1024
#define MAX_PATH_LEN 256
#define MAX_FILE_SIZE 1024*1024*1024 // 1 GB
#define MAX_FILES 2147483648
#define PORT 3000
#define MAX_CLIENTS 5
#define DEBUG_NONE 0
#define DEBUG_STEP 1
#define DEBUG_BREAK 2
#define CHUNK_SIZE 8192  // 8 KB chunks
#define SHARED_FOLDER_PATH "/Volumes/SharedContainer"
#define CPU_USAGE_THRESHOLD 80.0 // 80% CPU usage
#define MEMORY_USAGE_THRESHOLD 80.0 // 80% of soft limit
#define MAX_CPU_PRIORITY 39 // Maximum nice value
#define MIN_CPU_PRIORITY -20 // Minimum nice value
#define MAX_MEMORY_LIMIT 2147483648 // 2 GB max memory limit
#define MAX_HISTORY_LEN 100
#define MAX_LINE_LEN 1024
#define VERSION "v0.71"
#define OSXIEC_ARCHITECTURE "86_64"

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
    char current_directory[MAX_PATH_LEN];
    char last_executed_command[MAX_COMMAND_LEN];
    int num_processes;
    long memory_usage;
    char network_status[50];
    char **environment_variables;
    int num_env_vars;
} ContainerState;

ContainerState container_state = {0};

typedef struct {
    char commands[MAX_HISTORY_LEN][MAX_COMMAND_LEN];
    int count;
    int current;
} CommandHistory;

CommandHistory history = { .count = 0, .current = 0 };

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
                    fprintf(stderr, "File %s is too large (max %d bytes)\n", entry->d_name, MAX_FILE_SIZE);
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
    FILE* file = fopen("/proc/self/status", "r");
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
            container_state.environment_variables = realloc(container_state.environment_variables, (i + 1) * sizeof(char*));
            container_state.environment_variables[i] = strdup(environ[i]);
            container_state.num_env_vars++;
        } else if (strcmp(container_state.environment_variables[i], environ[i]) != 0) {
            free(container_state.environment_variables[i]);
            container_state.environment_variables[i] = strdup(environ[i]);
        }
    }
}

void print_container_state() {
    update_container_state();

    printf("Container State:\n");
    printf("  Current Directory: %s\n", container_state.current_directory);
    printf("  Last Executed Command: %s\n", container_state.last_executed_command);
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
        if (breakpoint) free(breakpoint);
        breakpoint = strdup(command + 6);
        debug_mode = DEBUG_BREAK;
    } else if (strcmp(command, "print") == 0 || strcmp(command, "p") == 0) {
        print_container_state();
    } else if (strncmp(command, "print ", 6) == 0 || strncmp(command, "p ", 2) == 0) {
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

    if (realpath(path, resolved_path) == NULL || realpath(base, resolved_base) == NULL) {
        return 0;
    }

    return strncmp(resolved_path, resolved_base, strlen(resolved_base)) == 0;
}


void execute_command(const char *command, const char *container_root) {
    if (command == NULL || strlen(command) == 0) {
        fprintf(stderr, "Error: Empty command\n");
        return;
    }

    if (debug_mode == DEBUG_STEP || (debug_mode == DEBUG_BREAK && breakpoint && strstr(command, breakpoint))) {
        printf("Debugger: Paused at command: %s\n", command);
        char *debug_cmd;
        while ((debug_cmd = readline("debug> ")) != NULL) {
            handle_debug_command(debug_cmd);
            free(debug_cmd);
            if (debug_mode == DEBUG_NONE) break;
        }
    }

    printf("Executing: %s\n", command);

    strncpy(container_state.last_executed_command, command, MAX_COMMAND_LEN - 1);
    container_state.last_executed_command[MAX_COMMAND_LEN - 1] = '\0';

    // Update current directory if it's a cd command
    if (strncmp(command, "cd ", 3) == 0) {
        const char *new_dir = command + 3;
        const char shared_folder_path[] = "/Volumes/SharedContainer";

        char current_path[PATH_MAX];
        if (getcwd(current_path, sizeof(current_path)) == NULL) {
            perror("Failed to get current directory");
            return;
        }

        if (is_subpath(new_dir, container_root) ||
            is_subpath(new_dir, shared_folder_path) ||
            (is_subpath(current_path, shared_folder_path) && strcmp(new_dir, container_root) == 0)) {
            if (chdir(new_dir) == 0) {
                getcwd(container_state.current_directory, MAX_PATH_LEN);
                printf("Changed directory to: %s\n", container_state.current_directory);
            } else {
                perror("Failed to change directory");
            }
            } else {
                fprintf(stderr, "Error: Cannot change directory outside of the container or shared folder.\n");
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

    int ret = posix_spawnp(&pid, args[0], &actions, &attr, args, environ);

    if (ret == 0) {
        if (waitpid(pid, &status, 0) != -1) {
            if (WIFEXITED(status)) {
                printf("Child process exited with status %d\n", WEXITSTATUS(status));
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
    // Note this is a work in progress, so it make not always provide correct results
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

    // Check container configuration
    if (config.container_uid == 0 || config.container_gid == 0) {
        printf("HIGH RISK: Container is running as root. This is a significant security risk.\n");
    }

    if (strcmp(config.network_mode, "host") == 0) {
        printf("HIGH RISK: Container is using host network mode. This can be a significant security risk.\n");
        printf("The host network error will not be revelenant if you use the vlan network.\n");
    }

    // Check resource limits
    if (config.memory_hard_limit == 0) {
        printf("MEDIUM RISK: No hard memory limit set. This could lead to resource exhaustion.\n");
    }

    if (config.cpu_priority == 0) {
        printf("LOW RISK: No CPU priority set. This could lead to resource contention.\n");
    }

    int num_files;
    fread(&num_files, sizeof(int), 1, file);

    regex_t regex;
    regcomp(&regex, "^[a-zA-Z0-9._-]+$", REG_EXTENDED);

    for (int i = 0; i < num_files; i++) {
        char file_name[MAX_PATH_LEN];
        size_t file_size;

        fread(file_name, sizeof(char), MAX_PATH_LEN, file);
        fread(&file_size, sizeof(size_t), 1, file);

        // Check for potentially dangerous file names
        if (strstr(file_name, "..") != NULL) {
            printf("HIGH RISK: File '%s' contains potentially dangerous '..' in its path.\n", file_name);
        }

        if (regexec(&regex, file_name, 0, NULL, 0) != 0) {
            printf("MEDIUM RISK: File '%s' has a potentially unsafe name.\n", file_name);
        }

        // Check for overly permissive file permissions
        if (strstr(file_name, ".sh") != NULL || strstr(file_name, ".py") || strstr(file_name, ".lua") != NULL) {
            printf("LOW RISK: Script file detected: '%s'. Ensure it has appropriate permissions.\n", file_name);
        }

        // Check for sensitive files
        if (strstr(file_name, "id_rsa") != NULL || strstr(file_name, ".pem") != NULL) {
            printf("HIGH RISK: Potential private key file detected: '%s'. Ensure it's properly secured.\n", file_name);
        }

        if (strstr(file_name, "password") != NULL || strstr(file_name, "secret") != NULL) {
            printf("HIGH RISK: Potential sensitive file detected: '%s'. Ensure it's properly secured.\n", file_name);
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
            printf("MEDIUM RISK: Insecure environment variable detected in file '%s'.\n", file_name);
        }

        // Check for insecure capabilities
        if (strstr(buffer, "CAP_SYS_ADMIN") != NULL) {
            printf("HIGH RISK: Insecure capability detected in file '%s'.\n", file_name);
        }

        // Check for insecure file permissions
        if (strstr(buffer, "chmod 777") != NULL) {
            printf("HIGH RISK: Insecure file permissions detected in file '%s'.\n", file_name);
        }

        // Check for hardcoded credentials
        regex_t pwd_regex;
        if (regcomp(&pwd_regex, "(password|api_key|secret)\\s*=\\s*['\"][^'\"]+['\"]", REG_EXTENDED | REG_ICASE) == 0) {
            if (regexec(&pwd_regex, buffer, 0, NULL, 0) == 0) {
                printf("HIGH RISK: Potential hardcoded credentials detected in file '%s'.\n", file_name);
            }
            regfree(&pwd_regex);
        }

        // Check for potential SQL injection vulnerabilities
        if (strstr(buffer, "SELECT") != NULL && strstr(buffer, "WHERE") != NULL && strstr(buffer, "+") != NULL) {
            printf("HIGH RISK: Potential SQL injection vulnerability detected in file '%s'.\n", file_name);
        }

        // Check for base64 encoded strings (potential hidden data)
        char *token = strtok(buffer, " \t\n");
        while (token != NULL) {
            if (strlen(token) > 20 && is_base64(token)) {
                printf("LOW RISK: Potential base64 encoded data detected in file '%s'. Verify if it contains sensitive information.\n", file_name);
                break;
            }
            token = strtok(NULL, " \t\n");
        }

        free(buffer);
    }

    regfree(&regex);

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
            } else if (strcmp(key, "memory_soft_limit") == 0) {
                config->memory_soft_limit = strtoul(value, NULL, 10);
            } else if (strcmp(key, "memory_hard_limit") == 0) {
                config->memory_hard_limit = strtoul(value, NULL, 10);
            } else if (strcmp(key, "cpu_priority") == 0) {
                config->cpu_priority = atoi(value);
            } else if (strcmp(key, "network_mode") == 0) {
                strncpy(config->network_mode, value, sizeof(config->network_mode) - 1);
            } else if (strcmp(key, "container_uid") == 0) {
                config->container_uid = atoi(value);
            } else if (strcmp(key, "container_gid") == 0) {
                config->container_gid = atoi(value);
            }
        }
    }

    fclose(file);
}


void containerize_directory(const char *dir_path, const char *output_file, const char *start_config_file, const char *container_config_file) {
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

    int num_files;

    // Initialize default config
    ContainerConfig config = {
        .name = "default_container",
        .memory_soft_limit = 384 * 1024 * 1024,
        .memory_hard_limit = 512 * 1024 * 1024,
        .cpu_priority = 20,
        .network_mode = "bridge",
        .container_uid = 1000,
        .container_gid = 1000,
        .start_config = ""
    };

    if (container_config_file) {
        read_config_file(container_config_file, &config);
    }

    if (start_config_file) {
        strncpy(config.start_config, start_config_file, MAX_PATH_LEN - 1);
        config.start_config[MAX_PATH_LEN - 1] = '\0';
    } else {
        config.start_config[0] = '\0';
    }

    num_files = read_files(dir_path, files, config.container_uid, config.container_gid);
    if (num_files < 0) {
        free(files);
        fclose(bin_file);
        exit(EXIT_FAILURE);
    }

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

void containerize_directory_with_bin_file(const char *dir_path, const char *input_bin_file, const char *output_file, const char *start_config_file, const char *container_config_file) {
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

    int num_files = 0;

    // Initialize default config
    ContainerConfig config = {
        .name = "default_container",
        .memory_soft_limit = 384 * 1024 * 1024,
        .memory_hard_limit = 512 * 1024 * 1024,
        .cpu_priority = 20,
        .network_mode = "bridge",
        .container_uid = 1000,
        .container_gid = 1000,
        .start_config = ""
    };

    // Load config from file if provided
    if (container_config_file) {
        read_config_file(container_config_file, &config);
    }

    if (start_config_file) {
        strncpy(config.start_config, start_config_file, MAX_PATH_LEN - 1);
        config.start_config[MAX_PATH_LEN - 1] = '\0';
    }

    // Read files from directory
    int dir_files = read_files(dir_path, files, config.container_uid, config.container_gid);
    if (dir_files < 0) {
        free(files);
        fclose(bin_file);
        exit(EXIT_FAILURE);
    }
    num_files += dir_files;

    // Read files from input bin file
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

        for (int i = 0; i < input_num_files; i++) {
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

        num_files += input_num_files;
        fclose(input_bin);
    }

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

        if (task_info(task, TASK_VM_INFO, (task_info_t)&vm_info, &count) == KERN_SUCCESS) {
            vm_size_t used_memory = vm_info.internal + vm_info.compressed;

            if (used_memory > config->memory_hard_limit) {
                fprintf(stderr, "Memory usage exceeded hard limit. Terminating process.\n");
                exit(1);
            } else if (used_memory > config->memory_soft_limit) {
                fprintf(stderr, "Warning: Memory usage exceeded soft limit. Clearing cache memory.\n");
                system("purge");
            }
        }

        sleep(1);
    }
}

void apply_resource_limits(const ContainerConfig *config) {
    // Note it applies basic limits, as it doesn't fully use the kernel
    // The reason why is that it would cause many permission issues, pottentially allow the containers to acces parts of the kernel they shouldn't be able to access
    setpriority(PRIO_PROCESS, 0, config->cpu_priority);

    // Start memory monitoring thread
    pthread_t memory_thread;
    if (pthread_create(&memory_thread, NULL, monitor_memory_usage, (void *)config) != 0) {
        perror("Failed to create memory monitoring thread");
    } else {
        printf("Memory monitoring started with soft limit %ld bytes and hard limit %ld bytes\n",
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
        if (sscanf(line, "container_name=%s", network.container_names[network.num_containers]) == 1) {
            network.num_containers++;
            continue;
        }
        if (sscanf(line, "container_ip=%s", network.container_ips[network.num_containers - 1]) == 1) {
            continue;
        }
    }

    fclose(file);
    return network;
}

void create_and_save_container_network(const char *name, int vlan_id) {
    ContainerNetwork network;
    strncpy(network.name, name, MAX_PATH_LEN - 1);
    network.vlan_id = vlan_id;
    network.num_containers = 0;

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
    fclose(file);

    printf("Created and saved network %s with VLAN ID %d\n", network.name, network.vlan_id);
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

void add_container_to_network(ContainerNetwork *network, const char *container_name) {
    if (network->num_containers < MAX_CLIENTS) {
        strncpy(network->container_names[network->num_containers], container_name, MAX_PATH_LEN - 1);

        // Dynamically assign IP address based on the number of containers
        char container_ip[16];
        snprintf(container_ip, sizeof(container_ip), "192.168.%d.%d", network->vlan_id, network->num_containers + 2);
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
    snprintf(ip_cmd, sizeof(ip_cmd), "ifconfig vlan%d create vlan %d vlandev en0 && ifconfig vlan%d inet %s/24 up",
             network->vlan_id, network->vlan_id, network->vlan_id, ip_address);
    system(ip_cmd);

    // Create a new file for VLAN rules
    char vlan_rules_file[64];
    snprintf(vlan_rules_file, sizeof(vlan_rules_file), "/etc/pf.vlan%d.conf", network->vlan_id);

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
        network->vlan_id,
        ip_address,
        network->vlan_id,
        network->vlan_id,
        network->vlan_id
    );
    fclose(vlan_pf_conf);

    // Add include statement to main pf.conf if not already present
    char include_cmd[256];
    snprintf(include_cmd, sizeof(include_cmd),
        "grep -q 'include \"%s\"' /etc/pf.conf || echo 'include \"%s\"' >> /etc/pf.conf",
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

void setup_network_isolation(ContainerConfig *config, ContainerNetwork *network) {
    if (strcmp(config->network_mode, "bridge") == 0) {
        config->vlan_id = network->vlan_id;

        // Dynamically assign IP address based on the number of containers
        char container_ip[16];
        snprintf(container_ip, sizeof(container_ip), "192.168.%d.%d", network->vlan_id, network->num_containers + 2);
        add_container_to_network(network, config->name);

        printf("Setting up bridge network. Container %s on VLAN %d with IP %s\n", config->name, config->vlan_id, container_ip);

        char vlan_cmd[256];
        snprintf(vlan_cmd, sizeof(vlan_cmd), "ifconfig vlan%d create vlan %d vlandev en0",
                 config->vlan_id, config->vlan_id);
        system(vlan_cmd);

        snprintf(vlan_cmd, sizeof(vlan_cmd), "ifconfig vlan%d inet %s/24 up", config->vlan_id, container_ip);
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
    snprintf(pf_rule, sizeof(pf_rule),
        "pass on vlan%d all\n",
        network->vlan_id);

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

    while ((bytes_received = recv(client_socket, command, sizeof(command) - 1, 0)) > 0) {
        command[bytes_received] = '\0';

        if (strcmp(command, "exit") == 0) {
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
        if ((client_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
            perror("accept");
            continue;
        }

        printf("New client connected\n");
        handle_client(client_socket, container_root);
    }
}

void scale_container_resources(long memory_soft_limit, long memory_hard_limit, int cpu_priority) {
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

void handle_script_file(const char *filename) {
    execute_script_file(filename);
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

    clock_t current_cpu_time = usage.ru_utime.tv_sec * 1000000 + usage.ru_utime.tv_usec +
                               usage.ru_stime.tv_sec * 1000000 + usage.ru_stime.tv_usec;

    double cpu_usage = 0.0;
    if (last_cpu_time != 0) {
        long wall_time_diff = (current_wall_time.tv_sec - last_wall_time.tv_sec) * 1000000 +
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
            double memory_usage_percent = (memory_used * 100.0) / config->memory_soft_limit;
            double cpu_usage = get_cpu_usage();

            bool should_scale = false;

            if (memory_usage_percent > MEMORY_USAGE_THRESHOLD && config->memory_soft_limit < MAX_MEMORY_LIMIT) {
                config->memory_soft_limit += memory_increment;
                config->memory_hard_limit += memory_increment;
                should_scale = true;
            }

            if (cpu_usage > CPU_USAGE_THRESHOLD && config->cpu_priority > MIN_CPU_PRIORITY) {
                config->cpu_priority = (config->cpu_priority > MIN_CPU_PRIORITY + cpu_priority_increment)
                    ? config->cpu_priority - cpu_priority_increment
                    : MIN_CPU_PRIORITY;
                should_scale = true;
            }

            if (should_scale) {
                apply_resource_limits(config);
                scale_count++;

                printf("Auto-scaled resources (Count: %d):\n", scale_count);
                printf("Memory Usage: %.2f%% (%ld / %ld bytes)\n",
                       memory_usage_percent, memory_used, config->memory_soft_limit);
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
    if (pthread_create(&auto_scale_thread, NULL, auto_scale_resources, (void *)config) != 0) {
        perror("Failed to create auto-scaling thread");
    } else {
        printf("Auto-scaling started\n");
    }
}

void print_current_resource_usage(ContainerConfig *config) {
    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage) == 0) {
        long memory_used = usage.ru_maxrss;
        double memory_usage_percent = (memory_used * 100.0) / config->memory_soft_limit;
        double cpu_usage = get_cpu_usage();

        printf("Current Resource Usage:\n");
        printf("Memory Usage: %.2f%% (%ld / %ld bytes)\n",
               memory_usage_percent, memory_used, config->memory_soft_limit);
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
        memmove(history.commands, history.commands + 1, (MAX_HISTORY_LEN - 1) * MAX_COMMAND_LEN);
        strncpy(history.commands[MAX_HISTORY_LEN - 1], command, MAX_COMMAND_LEN);
    }
}

void navigate_history(char *command, int *command_index, int *cursor_pos, int direction) {
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

void signal_handler(int signum) {
    stop_thread = 1;
}

void *logger_thread(void *arg) {
    FILE *log_file = fopen("/Volumes/Container/log.txt", "w");
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
            fprintf(log_file, "CPU Priority: %d\n", ((ContainerConfig *)arg)->cpu_priority);

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

void create_isolated_environment(FILE *bin_file, const char *bin_file_path, ContainerNetwork *network) {
    signal(SIGTERM, handle_signal);
    signal(SIGINT, handle_signal);
    signal(SIGSEGV, handle_signal);
    ContainerConfig config;
    fread(&config, sizeof(ContainerConfig), 1, bin_file);

    setup_network_isolation(&config, network);
    enable_container_communication(network);

    int num_files;
    fread(&num_files, sizeof(int), 1, bin_file);

    // Create shared folder if it doesn't exist
    char shared_folder_path[] = "/Volumes/SharedContainer";
    mkdir(shared_folder_path, 0755);

    // Create and mount disk image for file system isolation
    char disk_image_path[MAX_PATH_LEN];
    snprintf(disk_image_path, sizeof(disk_image_path), "/tmp/container_disk_%d.dmg", getpid());

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
             "hdiutil create -size %.2fg -fs HFS+ -volname \"%s\" %s",
             size_in_gb, bin_file_path, disk_image_path);

    system(create_disk_command);

    chmod(disk_image_path, 0644);  // rw-r--r--

    char mount_command[MAX_COMMAND_LEN];
    snprintf(mount_command, sizeof(mount_command), "hdiutil attach %s", disk_image_path);
    system(mount_command);

    char container_root[MAX_PATH_LEN];
    snprintf(container_root, sizeof(container_root), "/Volumes/%s", bin_file_path);

    // Create a symbolic link to the shared folder
    char shared_mount_point[MAX_PATH_LEN];
    snprintf(shared_mount_point, sizeof(shared_mount_point), "%s/shared", container_root);
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

    chmod(container_root, 0755);

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

    apply_resource_limits(&config);

    // Updated sandbox profile
    char sandbox_profile[1024];
    snprintf(sandbox_profile, sizeof(sandbox_profile),
        "(version 1)"
        "(deny default)"
        "(allow process-fork)"
        "(allow file-read*)"
        "(allow file-write* (subpath \"%s\"))"
        "(allow file-read* (subpath \"%s\"))"
        "(allow file-read* (literal \"%s\"))"
        "(allow file-read* (subpath \"/usr/lib\"))"
        "(allow file-read* (subpath \"/usr/bin\"))"
        "(allow file-read* (subpath \"/bin\"))"
        "(allow file-read* (subpath \"/System\"))"
        "(allow file-read* (subpath \"%s\"))"
        "(allow file-read* (subpath \"/Applications/Xcode.app\"))"
        "(allow file-write* (subpath \"%s\"))"
        "(allow sysctl-read)"
        "(allow mach-lookup)"
        "(allow network-outbound (remote ip))"
        "(allow network-inbound (local ip))"
        "(allow process-exec (subpath \"/usr/bin\"))"
        "(allow process-exec (subpath \"/Applications/Xcode.app\"))"
        "(allow process-exec (subpath \"/bin\"))"
        "(allow process-exec (subpath \"%s\"))",
        container_root, container_root, bin_file_path,
        shared_mount_point, shared_mount_point, container_root
    );

    char *error;
    if (sandbox_init(sandbox_profile, 0, &error) != 0) {
        fprintf(stderr, "sandbox_init failed: %s\n", error);
        sandbox_free_error(error);
        exit(1);
    }

    printf("\n=== Container %s Terminal ===\n", bin_file_path);
    printf("Enter commands (type 'exit' to quit, help for help):\n");
    printf("If you just ran the container ignore the first log file error");

    // Start the network listener in a separate thread
    pthread_t network_thread;
    if (pthread_create(&network_thread, NULL, (void *(*)(void *))start_network_listener, NULL) != 0) {
        perror("Failed to create network listener thread");
    }

    if (config.start_config[0] != '\0') {
        char start_config_path[MAX_PATH_LEN];
        snprintf(start_config_path, sizeof(start_config_path), "%s/%s", container_root, config.start_config);
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

        printf("> ");
        fflush(stdout);

        int ch;
        while ((ch = getchar()) != EOF) {
            if (ch == 27) { // ESC key
                getchar(); // Skip the next character
                ch = getchar(); // Get the actual key code
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
                    memmove(&command[cursor_pos - 1], &command[cursor_pos], command_index - cursor_pos + 1);
                    command_index--;
                    cursor_pos--;
                    printf("%s", &command[cursor_pos]);
                    move_cursor_left(command_index - cursor_pos);
                }
            } else if (ch == '\n' || ch == '\r') { // Enter key
                command[command_index] = '\0';
                set_terminal_canonical_mode();
                usleep(10000); // 10ms delay

                if (strcmp(command, "exit") == 0) goto exit_loop;
                if (strcmp(command, "debug") == 0) {
                    debug_mode = DEBUG_STEP;
                    printf("Entered debug mode. Type 'help' for debug commands.\n");
                } else if (strncmp(command, "scale", 5) == 0) {
                    long memory_soft_limit, memory_hard_limit;
                    int cpu_priority;
                    if (sscanf(command, "scale %ld %ld %d", &memory_soft_limit, &memory_hard_limit, &cpu_priority) == 3) {
                        scale_container_resources(memory_soft_limit, memory_hard_limit, cpu_priority);
                    } else {
                        printf("Usage: scale <memory_soft_limit> <memory_hard_limit> <cpu_priority>\n");
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
                } else if (strcmp(command, "help") == 0) {
                    printf("Commands:\n");
                    printf("  exit: Exit the container\n");
                    printf("  debug: Enter debug mode\n");
                    printf("  scale <memory_soft_limit> <memory_hard_limit> <cpu_priority>: Set memory limits and CPU priority\n");
                    printf("  xs <script_content>: Execute a script in the container\n");
                    printf("  osxs <filename>: Execute a script file in the container\n");
                    printf("  autoscale: Start automatic resource scaling\n");
                    printf("  status: Print current resource usage\n");
                    printf("  help: Print this help message\n");
                    printf("  stop: Stops the container and save its state\n");
                } else if (strcmp(command, "stop") == 0) {
                    printf("Stopping container...\n");

                    // Save the container state
                    char state_file_path[MAX_PATH_LEN];
                    time_t now = time(NULL);

                    // Construct the state file path using the Unix timestamp
                    snprintf(state_file_path, sizeof(state_file_path), "%s/%ld_%s", container_root, now, bin_file_path);

                    // state_file_path now includes the date
                    FILE *state_file = fopen(state_file_path, "wb");
                    if (state_file == NULL) {
                        perror("Error creating container state file");
                    } else {
                        // Save the container configuration
                        fwrite(&config, sizeof(ContainerConfig), 1, state_file);

                        // Save the environment variables
                        fwrite(&container_state, sizeof(ContainerState), 1, state_file);
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
                snprintf(log_file_path, sizeof(log_file_path), "%s/log.txt", container_root);
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
                    memmove(&command[cursor_pos + 1], &command[cursor_pos], command_index - cursor_pos + 1);
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
    ContainerConfig config;
    fread(&config, sizeof(ContainerConfig), 1, bin_file);

    int num_files;
    fread(&num_files, sizeof(int), 1, bin_file);

    char shared_folder_path[] = "/Volumes/SharedContainer";
    mkdir(shared_folder_path, 0755);

    char disk_image_path[MAX_PATH_LEN];
    snprintf(disk_image_path, sizeof(disk_image_path), "/tmp/container_disk_%d.dmg", getpid());

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
             "hdiutil create -size %.2fg -fs HFS+ -volname \"%s\" %s",
             size_in_gb, bin_file_path, disk_image_path);

    system(create_disk_command);

    chmod(disk_image_path, 0644);

    char mount_command[MAX_COMMAND_LEN];
    snprintf(mount_command, sizeof(mount_command), "hdiutil attach %s", disk_image_path);
    system(mount_command);

    // Use bin_file_path as the root volume name
    char container_root[MAX_PATH_LEN];
    snprintf(container_root, sizeof(container_root), "/Volumes/%s", bin_file_path);

    char shared_mount_point[MAX_PATH_LEN];
    snprintf(shared_mount_point, sizeof(shared_mount_point), "%s/shared", container_root);
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

    chmod(container_root, 0755);

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

    apply_resource_limits(&config);

    char sandbox_profile[1024];
    snprintf(sandbox_profile, sizeof(sandbox_profile),
        "(version 1)"
        "(deny default)"
        "(allow process-fork)"
        "(allow file-read*)"
        "(allow file-write* (subpath \"%s\"))"
        "(allow file-read* (subpath \"%s\"))"
        "(allow file-read* (literal \"%s\"))"
        "(allow file-read* (subpath \"/usr/lib\"))"
        "(allow file-read* (subpath \"/usr/bin\"))"
        "(allow file-read* (subpath \"/bin\"))"
        "(allow file-read* (subpath \"/System\"))"
        "(allow file-read* (subpath \"%s\"))"
        "(allow file-read* (subpath \"/Applications/Xcode.app\"))"
        "(allow file-write* (subpath \"%s\"))"
        "(allow sysctl-read)"
        "(allow mach-lookup)"
        "(allow network-outbound (remote ip))"
        "(allow network-inbound (local ip))"
        "(allow process-exec (subpath \"/usr/bin\"))"
        "(allow process-exec (subpath \"/Applications/Xcode.app\"))"
        "(allow process-exec (subpath \"/bin\"))"
        "(allow process-exec (subpath \"%s\"))",
        container_root, container_root, bin_file_path,
        shared_mount_point, shared_mount_point, container_root
    );

    char *error;
    if (sandbox_init(sandbox_profile, 0, &error) != 0) {
        fprintf(stderr, "sandbox_init failed: %s\n", error);
        sandbox_free_error(error);
        exit(1);
    }

    printf("\n=== Container %s Terminal ===\n", bin_file_path);
    printf("Enter commands (type 'exit' to quit, help for help):\n");
    printf("If you just ran the container ignore the first log file error");

    if (config.start_config[0] != '\0') {
        char start_config_path[MAX_PATH_LEN];
        snprintf(start_config_path, sizeof(start_config_path), "%s/%s", container_root, config.start_config);
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

        printf("> ");
        fflush(stdout);

        int ch;
        while ((ch = getchar()) != EOF) {
            if (ch == 27) { // ESC key
                getchar(); // Skip the next character
                ch = getchar(); // Get the actual key code
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
                    memmove(&command[cursor_pos - 1], &command[cursor_pos], command_index - cursor_pos + 1);
                    command_index--;
                    cursor_pos--;
                    printf("%s", &command[cursor_pos]);
                    move_cursor_left(command_index - cursor_pos);
                }
            } else if (ch == '\n' || ch == '\r') { // Enter key
                command[command_index] = '\0';
                set_terminal_canonical_mode();
                usleep(10000); // 10ms delay

                if (strcmp(command, "exit") == 0) goto exit_loop;
                if (strcmp(command, "debug") == 0) {
                    debug_mode = DEBUG_STEP;
                    printf("Entered debug mode. Type 'help' for debug commands.\n");
                } else if (strncmp(command, "scale", 5) == 0) {
                    long memory_soft_limit, memory_hard_limit;
                    int cpu_priority;
                    if (sscanf(command, "scale %ld %ld %d", &memory_soft_limit, &memory_hard_limit, &cpu_priority) == 3) {
                        scale_container_resources(memory_soft_limit, memory_hard_limit, cpu_priority);
                    } else {
                        printf("Usage: scale <memory_soft_limit> <memory_hard_limit> <cpu_priority>\n");
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
                } else if (strcmp(command, "help") == 0) {
                    printf("Commands:\n");
                    printf("  exit: Exit the container\n");
                    printf("  debug: Enter debug mode\n");
                    printf("  scale <memory_soft_limit> <memory_hard_limit> <cpu_priority>: Set memory limits and CPU priority\n");
                    printf("  xs <script_content>: Execute a script in the container\n");
                    printf("  osxs <filename>: Execute a script file in the container\n");
                    printf("  autoscale: Start automatic resource scaling\n");
                    printf("  status: Print current resource usage\n");
                    printf("  help: Print this help message\n");
                    printf(" stop: Stops the container and saves its state\n");
                } else if (strcmp(command, "stop") == 0) {
                    printf("Stopping container...\n");

                    // Save the container state
                    char state_file_path[MAX_PATH_LEN];
                    snprintf(state_file_path, sizeof(state_file_path), "%s/%s", container_root, bin_file_path);
                    FILE *state_file = fopen(state_file_path, "wb");
                    if (state_file == NULL) {
                        perror("Error creating container state file");
                    } else {
                        // Save the container configuration
                        fwrite(&config, sizeof(ContainerConfig), 1, state_file);

                        // Save the environment variables
                        fwrite(&container_state, sizeof(ContainerState), 1, state_file);
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
                snprintf(log_file_path, sizeof(log_file_path), "%s/log.txt", container_root);
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
                    memmove(&command[cursor_pos + 1], &command[cursor_pos], command_index - cursor_pos + 1);
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

void download_file(const char* file_name) {
    CURL *curl;
    FILE *fp;
    CURLcode res;
    curl = curl_easy_init();
    if(curl) {
        char save_path[256];
        snprintf(save_path, sizeof(save_path), "./%s", file_name);
        fp = fopen(save_path, "wb");
        char url[256];
        snprintf(url, sizeof(url), "https://osxiec-file-server-1.onrender.com/files/%s", file_name);
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
        res = curl_easy_perform(curl);
        if(res != CURLE_OK)
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        fclose(fp);
        curl_easy_cleanup(curl);
    }
}

struct Memory {
    char *response;
    size_t size;
};

static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp) {
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
        snprintf(url, sizeof(url), "https://osxiec-file-server-1.onrender.com/search?term=%s", term);

        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

        res = curl_easy_perform(curl);

        if (res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        } else {
            printf("Search results:\n%s\n", chunk.response);
        }

        curl_easy_cleanup(curl);
    }

    free(chunk.response);
    curl_global_cleanup();
}

void upload_file(const char *filename, const char *username, const char *password, const char *description) {
    CURL *curl;
    CURLcode res;
    struct curl_httppost *formpost = NULL;
    struct curl_httppost *lastptr = NULL;

    curl_global_init(CURL_GLOBAL_ALL);

    // Create the form
    curl_formadd(&formpost, &lastptr,
                 CURLFORM_COPYNAME, "file",
                 CURLFORM_FILE, filename,
                 CURLFORM_END);

    curl_formadd(&formpost, &lastptr,
                 CURLFORM_COPYNAME, "username",
                 CURLFORM_COPYCONTENTS, username,
                 CURLFORM_END);

    curl_formadd(&formpost, &lastptr,
                 CURLFORM_COPYNAME, "password",
                 CURLFORM_COPYCONTENTS, password,
                 CURLFORM_END);

    curl_formadd(&formpost, &lastptr,
                 CURLFORM_COPYNAME, "description",
                 CURLFORM_COPYCONTENTS, description,
                 CURLFORM_END);

    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "https://osxiec-file-server-1.onrender.com/upload");
        curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost);

        // Perform the request
        res = curl_easy_perform(curl);

        // Check for errors
        if (res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        } else {
            printf("File uploaded successfully.\n");
        }

        // Clean up
        curl_easy_cleanup(curl);
    }

    curl_formfree(formpost);
    curl_global_cleanup();
}

void convert_to_docker(const char *osxiec_file, const char *output_dir, const char *base_image, const char *custom_dockerfile) {
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
        snprintf(cmd, sizeof(cmd), "cp %s %s/Dockerfile", custom_dockerfile, output_dir);
        if (system(cmd) != 0) {
            perror("Error copying custom Dockerfile");
            fclose(bin_file);
            return;
        }
    } else {
        snprintf(dockerfile_path, sizeof(dockerfile_path), "%s/Dockerfile", output_dir);
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
        if (dockerfile) fclose(dockerfile);
        fclose(bin_file);
        return;
    }

    char buffer[CHUNK_SIZE];
    for (int i = 0; i < num_files; i++) {
        char file_name[MAX_PATH_LEN];
        size_t file_size;

        if (fread(file_name, sizeof(char), MAX_PATH_LEN, bin_file) != MAX_PATH_LEN ||
            fread(&file_size, sizeof(size_t), 1, bin_file) != 1) {
            perror("Error reading file metadata");
            if (dockerfile) fclose(dockerfile);
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
        fprintf(dockerfile, "\nENV MEMORY_SOFT_LIMIT=%ld\n", config.memory_soft_limit);
        fprintf(dockerfile, "ENV MEMORY_HARD_LIMIT=%ld\n", config.memory_hard_limit);
        fprintf(dockerfile, "ENV CPU_PRIORITY=%d\n", config.cpu_priority);

        if (strcmp(config.network_mode, "host") == 0) {
            fprintf(dockerfile, "\n# Using host network mode\n");
        } else if (strcmp(config.network_mode, "bridge") == 0) {
            fprintf(dockerfile, "\n# Using bridge network mode\n");
        }

        if (config.start_config[0] != '\0') {
            fprintf(dockerfile, "\nCMD [\"/bin/sh\", \"-c\", \"while read cmd; do $cmd; done < %s\"]\n", config.start_config);
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

    if (source_dir[0] == '\0' || container_file[0] == '\0' || network_name[0] == '\0') {
        fprintf(stderr, "Error: Missing required configuration in config file\n");
        return;
    }

    // Contain the directory
    containerize_directory(source_dir, container_file, start_config[0] != '\0' ? start_config : NULL, container_config[0] != '\0' ? container_config : NULL);
    printf("Directory contents containerized into '%s'.\n", container_file);

    // Load network configuration
    ContainerNetwork network = load_container_network(network_name);

    if (network.vlan_id == 0) {
        fprintf(stderr, "Failed to load network configuration for %s\n", network_name);
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
    snprintf(command, sizeof(command), "hdiutil detach -force /Volumes/%s", volume_name);
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

        if (fread(file_name, sizeof(char), MAX_PATH_LEN, bin_file) != MAX_PATH_LEN ||
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

void convert_to_oci(const char *osxiec_file, const char *output_dir, const char *arch, const char *author, const char *created) {
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
    json_object_object_add(config_json, "architecture", json_object_new_string(arch));
    json_object_object_add(config_json, "author", json_object_new_string(author));
    json_object_object_add(config_json, "created", json_object_new_string(created));
    json_object_object_add(config_json, "ociVersion", json_object_new_string("1.0.0"));
    json_object_object_add(config_json, "root", json_object_new_object());
    struct json_object *root_object = json_object_new_object();
    struct json_object *path_object = json_object_new_string("");
    json_object_object_add(root_object, "path", path_object);
    json_object_object_add(config_json, "root", root_object);


    // Create config blob
    char config_blob_path[MAX_PATH_LEN];
    snprintf(config_blob_path, sizeof(config_blob_path), "%s/config.json", blobs_dir);
    FILE *config_blob = fopen(config_blob_path, "w");
    if (config_blob == NULL) {
        perror("Error creating config blob");
        fclose(bin_file);
        json_object_put(config_json);
        return;
    }
    fprintf(config_blob, "%s", json_object_to_json_string_ext(config_json, JSON_C_TO_STRING_PRETTY));
    fclose(config_blob);

    // Prepare manifest JSON
    json_object *manifest_json = json_object_new_object();
    json_object_object_add(manifest_json, "schemaVersion", json_object_new_int(2));
    json_object_object_add(manifest_json, "mediaType", json_object_new_string("application/vnd.oci.image.manifest.v1+json"));
    json_object_object_add(manifest_json, "config", json_object_new_object());
    json_object_object_add(json_object_object_get(manifest_json, "config"), "mediaType", json_object_new_string("application/vnd.oci.image.config.v1+json"));
    json_object_object_add(json_object_object_get(manifest_json, "config"), "size", json_object_new_int64(strlen(json_object_to_json_string(config_json))));
    json_object_object_add(json_object_object_get(manifest_json, "config"), "digest", json_object_new_string("sha256:configdigest")); // Replace with actual digest

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
            *last_slash = '\0'; // Temporarily null-terminate the path to create directories
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
        json_object_object_add(layer, "mediaType", json_object_new_string("application/vnd.oci.image.layer.v1.tar"));
        json_object_object_add(layer, "size", json_object_new_int64(file_size));
        json_object_object_add(layer, "digest", json_object_new_string("sha256:layerdigest")); // Replace with actual digest
        json_object_array_add(layers_array, layer);
    }

    // Write manifest
    char manifest_path[MAX_PATH_LEN];
    snprintf(manifest_path, sizeof(manifest_path), "%s/manifest.json", output_dir);
    FILE *manifest_file = fopen(manifest_path, "w");
    if (manifest_file == NULL) {
        perror("Error creating manifest file");
        fclose(bin_file);
        json_object_put(config_json);
        json_object_put(manifest_json);
        return;
    }
    fprintf(manifest_file, "%s", json_object_to_json_string_ext(manifest_json, JSON_C_TO_STRING_PRETTY));
    fclose(manifest_file);

    fclose(bin_file);
    json_object_put(config_json);
    json_object_put(manifest_json);
    printf("OCI container structure created in %s\n", output_dir);
}

char* find_latest_bin_file(const char *volume_name) {
    DIR *dir;
    struct dirent *entry;
    char *latest_file_path = NULL;
    time_t latest_timestamp = 0;
    char search_directory[MAX_PATH_LEN];

    // Format the search directory path
    snprintf(search_directory, sizeof(search_directory), "/Volumes/%s", volume_name);

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
                snprintf(latest_file_path, MAX_PATH_LEN, "%s/%s", search_directory, entry->d_name);
            }
        }
    }
    closedir(dir);

    return latest_file_path;
}

int copy_file(const char *source, const char *destination_folder, const char *new_file_name) {
    // Construct the full path for the destination file
    char destination[MAX_PATH_LEN];
    snprintf(destination, sizeof(destination), "%s/%s", destination_folder, new_file_name);

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
    char *temp = realloc(*response_ptr, total_size + ( *response_ptr ? strlen(*response_ptr) : 0 ) + 1);
    if (temp == NULL) {
        fprintf(stderr, "Failed to allocate memory.\n");
        return 0; // Abort the transfer
    }
    *response_ptr = temp;

    // Append new data to the response buffer
    if (*response_ptr) {
        memcpy(*response_ptr + ( *response_ptr ? strlen(*response_ptr) : 0 ), contents, total_size);
        (*response_ptr)[total_size + ( *response_ptr ? strlen(*response_ptr) : 0 )] = '\0'; // Null-terminate
    }

    return total_size;
}


char* fetch_latest_version(void) {
    CURL *curl;
    CURLcode res;
    char *latest_version = NULL;

    curl = curl_easy_init();
    if(curl) {
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "User-Agent: osxiec-update-checker");

        curl_easy_setopt(curl, CURLOPT_URL, "https://api.github.com/repos/Okerew/osxiec/releases/latest");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        char *response = NULL;

        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

        res = curl_easy_perform(curl);

        if(res == CURLE_OK) {
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

int compare_versions(const char* v1, const char* v2) {
    int a, b, c, d, e, f;
    sscanf(v1, "%d.%d.%d", &a, &b, &c);
    sscanf(v2, "%d.%d.%d", &d, &e, &f);
    if (a != d) return a - d;
    if (b != e) return b - e;
    return c - f;
}

int main(int argc, char *argv[]) {
    PluginManager plugin_manager;
    plugin_manager_init(&plugin_manager);

    // Get the user's home directory
    const char* home_dir = getenv("HOME");
    if (home_dir == NULL) {
        struct passwd* pwd = getpwuid(getuid());
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
            fprintf(stderr, "Error creating .osxiec directory: %s\n", strerror(errno));
            // Continue execution, as the program can still function without plugins
        }

        // Now create the plugins directory
        if (mkdir(plugin_dir, 0755) == -1) {
            fprintf(stderr, "Error creating plugin directory %s: %s\n", plugin_dir, strerror(errno));
            // Continue execution, as the program can still function without plugins
        } else {
            printf("Created plugin directory: %s\n", plugin_dir);
        }
    }

    // Load plugins from the directory
    DIR* dir = opendir(plugin_dir);
    if (dir) {
        struct dirent* entry;
        while ((entry = readdir(dir)) != NULL) {
            if (entry->d_type == DT_REG) { // Regular file
                char plugin_path[MAX_PATH_LEN];
                snprintf(plugin_path, sizeof(plugin_path), "%s/%s", plugin_dir, entry->d_name);
                plugin_manager_load(&plugin_manager, plugin_path);
            }
        }
        closedir(dir);
    }
    if (argc < 2) {
        fprintf(stderr, "Unknown command: %s\n" , argv[0]);
        return EXIT_FAILURE;
    }

    if (strcmp(argv[1], "-contain") == 0) {
        if (argc < 4) {
            fprintf(stderr, "Usage for containerize: %s -contain <directory_path> <output_file> [start_config_file] [container_config_file]\n", argv[0]);
            return EXIT_FAILURE;
        }
        if (geteuid() != 0) {
            fprintf(stderr, "This program must be run as root. Try using sudo.\n");
            return EXIT_FAILURE;
        }

        const char *start_config_file = (argc > 4) ? argv[4] : NULL;
        const char *container_config_file = (argc > 5) ? argv[5] : NULL;
        containerize_directory(argv[2], argv[3], start_config_file, container_config_file);
        printf("Directory contents containerized into '%s'.\n", argv[3]);
    } else if (strcmp(argv[1], "-craft") == 0) {
        if (argc < 5) {
            fprintf(stderr, "Usage for craft: %s -craft <directory_path> <input_bin_file> <output_file> <start_config_file> <container_config_file>\n", argv[0]);
            return EXIT_FAILURE;
        }
        if (geteuid() != 0) {
            fprintf(stderr, "This program must be run as root. Try using sudo.\n");
            return EXIT_FAILURE;
        }

        const char *start_config_file = (argc > 5) ? argv[5] : NULL;
        const char *container_config_file = (argc > 6) ? argv[6] : NULL;
        containerize_directory_with_bin_file(argv[2], argv[3], argv[4], start_config_file, container_config_file);
        printf("Directory contents containerized into '%s'.\n", argv[4]);
    } else if (strcmp(argv[1], "-oexec") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage for execute: %s -execute <bin_file> [-port <port>]\n", argv[0]);
            return EXIT_FAILURE;
        }

        FILE *bin_file = fopen(argv[2], "rb");
        if (bin_file == NULL) {
            perror("Error opening binary file");
            return EXIT_FAILURE;
        }

        ocreate_isolated_environment(bin_file, argv[2]);
        fclose(bin_file);
    } else if (strcmp(argv[1], "-network") == 0) {
        if (argc < 4) {
            fprintf(stderr, "Usage: %s -network <create|remove> <name> [vlan_id]\n", argv[0]);
            return EXIT_FAILURE;
        }

        if (strcmp(argv[2], "create") == 0) {
            if (argc < 5) {
                fprintf(stderr, "Usage: %s -network create <name> <vlan_id>\n", argv[0]);
                return EXIT_FAILURE;
            }
            create_and_save_container_network(argv[3], atoi(argv[4]));
            ContainerNetwork network = load_container_network(argv[3]);
            setup_pf_rules(&network);
        }
        else if (strcmp(argv[2], "remove") == 0) {
            remove_container_network(argv[3]);
        }
        else {
            fprintf(stderr, "Unknown network command: %s\n", argv[2]);
            return EXIT_FAILURE;
        }
    }
    else if (strcmp(argv[1], "-run") == 0) {
        if (argc < 4) {
            fprintf(stderr, "Usage: %s -run <container_file> <network_name> [-port <port>]\n", argv[0]);
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
    } else if (strcmp(argv[1], "-start") == 0) {
        if (argc < 4) {
            fprintf(stderr, "Usage: %s -start <volume_name> <network_name> [-port <port>]\n", argv[0]);
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
        snprintf(full_dest_path, sizeof(full_dest_path), "%s/%s", dest_folder, volume_name);

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
    } else if (strcmp(argv[1], "-ostart") == 0) {
        if (argc < 2) {
            fprintf(stderr, "Usage: %s -ostart <volume_name>\n", argv[0]);
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
        snprintf(full_dest_path, sizeof(full_dest_path), "%s/%s", dest_folder, volume_name);

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
            fprintf(stderr, "Usage: %s -upload <filename> <username> <password> <description>\n", argv[0]);
            return EXIT_FAILURE;
        }
        upload_file(argv[2], argv[3], argv[4], argv[5]);
    } else if (strcmp(argv[1], "-convert-to-docker") == 0) {
        if (argc < 5 || argc > 6) {
            fprintf(stderr, "Usage: %s -convert-to-docker <bin_file> <output_directory> <base_image> [custom_dockerfile]\n", argv[0]);
            return EXIT_FAILURE;
        }
        const char *custom_dockerfile = (argc == 6) ? argv[5] : NULL;
        convert_to_docker(argv[2], argv[3], argv[4], custom_dockerfile);
    } else if (strcmp(argv[1], "-convert-to-oci") == 0) {
        if (argc < 6 || argc > 7) {
            fprintf(stderr, "Usage: %s -convert-to-oci <bin_file> <output_directory> <arch> <author> <date>\n", argv[0]);
            return EXIT_FAILURE;
        }
        convert_to_oci(argv[2], argv[3], argv[4], argv[5], argv[6]);
    } else if (strcmp(argv[1], "-deploy") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: %s -deploy <config_file> [-port <port>]\n", argv[0]);
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
        clean_container_dmgs();
        printf("Cleaned up container disk images from /tmp directory.\n");
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
            fprintf(stderr, "Usage: %s -extract <container_file> <output_directory>\n", argv[0]);
            return EXIT_FAILURE;
        }
        extract_container(argv[2], argv[3]);
    } else if (strcmp(argv[1], "-help") == 0) {
        printf("Available commands:\n");
        printf("  -contain <directory_path> <output_file> <path_to_start_config_file> <path_to_container_config_file>\n");
        printf("Contains a directory into a container file\n");
        printf(" -craft <directory_path> <input_bin_file> <output_file> <path_to_start_config_file> <path_to_container_config_file>\n");
        printf("Crafts a container file from a directory and a bin file\n");
        printf(" -oexec <container_file>\n");
        printf("Executes a container file in offline mode\n");
        printf(" -start <container_file> <network_name> [-port <port>]\n");
        printf("Starts a stopped container");
        printf(" -ostart <container_file> <network_name> [-port <port>]\n");
        printf("Starts a stopped container in offline mode");
        printf("  -network <create|remove> <name> [vlan_id>\n");
        printf("Manages the vlan network\n");
        printf("  -run <container_file> <network_name> [-port <port>]\n");
        printf("Runs a container file with a vlan network\n");
        printf("  -pull <file_name>\n");
        printf("Pulls a container from Osxiec Hub\n");
        printf("  -search <search_term>\n");
        printf("Searches for a container in Osxiec Hub\n");
        printf("  -upload <filename> <username> <password> <description>\n");
        printf("Uploads a file to Osxiec Hub\n");
        printf("  -convert-to-docker <bin_file> <output_directory> <base_image> [custom_dockerfile]\n");
        printf("Converts a binary file to a docker image\n");
        printf("  -convert-to-oci <bin_file> <output_directory> <arch> <author> <date>\n");
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
        printf("  -update\n");
        printf("Checks for updates and updates the current version\n");
    } else if (strcmp(argv[1], "--version") == 0) {
        char* latest_version = fetch_latest_version();
        if (latest_version) {
            int comparison = compare_versions(VERSION, latest_version);
            if (comparison < 0) {
                printf("An update is available. Latest version: %s\n", latest_version);
                printf("Your current version: %s\n", VERSION);
                printf("Please visit https://github.com/Okerew/osxiec/releases/latest to update.\n");
            } else if (comparison == 0) {
                printf("You are running the latest version (%s).\n", VERSION);
            }
            free(latest_version);
        } else {
            printf("Failed to check for updates. Please check your internet connection.\n");
            printf("Your current version: %s\n", VERSION);
        }
    } else if (strcmp(argv[1], "-update") == 0) {
        char* latest_version = fetch_latest_version();
        if (latest_version) {
            int comparison = compare_versions(VERSION, latest_version);
            if (comparison < 0) {
                printf("An update is available. Latest version: %s\n", latest_version);
                printf("Your current version: %s\n", VERSION);
                if (strcmp(OSXIEC_ARCHITECTURE, "arm64") == 0) {
                    char update_command[MAX_COMMAND_LEN];
                    sprintf(update_command, "curl -L -o osxiec_cli.tar.gz https://github.com/Okerew/osxiec/releases/download/%s/osxiec_cli.tar.gz", latest_version);
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
                    sprintf(update_command, "curl -L -o osxiec_cli_86_64.tar.gz https://github.com/Okerew/osxiec/releases/download/%s/osxiec_cli.tar.gz", latest_version);
                    system(update_command);
                    system("tar -xvzf osxiec_cli_86_64.tar.gz");
                    const char *path = "osxiec_cli_86_64";

                    if (chdir(path) != 0) {
                        perror("chdir() to 'osxiec_cli' failed");
                        return 1;
                    }

                    system("sudo sh install.sh");
                }
                else {
                    printf("There was some error while updating. Please visit https://github.com/Okerew/osxiec/releases/latest to update.\n");
                }
            } else if (comparison == 0) {
                printf("You are running the latest version (%s).\n", VERSION);
            }
            free(latest_version);
        } else {
            printf("Failed to check for updates. Please check your internet connection.\n");
            printf("Your current version: %s\n", VERSION);
        }
    } else if (strcmp(argv[1], "-api") == 0) {
        if (strcmp(argv[2], "execute_command") == 0) {
            execute_command(argv[3], argv[4]);
        }
        else if(strcmp(argv[2], "copy_file") == 0) {
            copy_file(argv[3], argv[4], argv[5]);
        }
        else if(strcmp(argv[2], "execute_script_file") == 0) {
            execute_script_file(argv[3]);
        }
        else if (strcmp(argv[2], "get_ip_address") == 0) {
            char* ip_address = get_ip_address();
            printf("%s\n", ip_address);
        }
        else if (strcmp(argv[2], "isbase64") == 0) {
            int value_is_base64 = is_base64(argv[3]);
            printf("%d\n", value_is_base64);
        }
        else if (strcmp(argv[2], "find_latest_bin_file") == 0) {
            char* latest_bin_file = find_latest_bin_file(argv[3]);
            printf("%s\n", latest_bin_file);
        }
        else if (strcmp(argv[2], "create_directories") == 0) {
            create_directories(argv[3]);
        }
        else if (strcmp(argv[2], "execute_start_config") == 0) {
            execute_start_config(argv[3], argv[4]);
        }
        else if (strcmp(argv[2], "start_network_listener") == 0) {
            start_network_listener(argv[1]);
        }
        else {
            printf("This futures is not accessible in the api\n");
        }
    } else {
        fprintf(stderr, "Unknown command: %s\n", argv[1]);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
