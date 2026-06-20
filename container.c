#include "globals/globals.h"
#include "log/log.h"
#include "osxiec.h"
#include "osxiec_script/osxiec_script.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <curl/curl.h>
#include <dirent.h>
#include <errno.h>
#include <json-c/json.h>
#include <libgen.h>
#include <mach-o/dyld.h>
#include <mach/mach.h>
#include <pthread.h>
#include <pwd.h>
#include <readline/history.h>
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

#define MAX_FILE_SIZE 1024 * 1024 * 1024
#define MAX_FILES 100000
#define CHUNK_SIZE 8192
#define SHARED_FOLDER_PATH "/Volumes/SharedContainer"
#define MAX_DEPS 256
#define MAX_VAR_LEN 1024

extern char **environ;

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
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
          continue;
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

        if (chmod(file_path, 0755) != 0) {
          perror("Error setting file permissions");
          free(files[num_files].data);
          closedir(dir);
          return -1;
        }

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
  signal(SIGBUS, handle_signal);
  signal(SIGILL, handle_signal);
  signal(SIGFPE, handle_signal);
  signal(SIGABRT, handle_signal);

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

  // The interactive container runs in this process after dropping privileges
  // below, so no separate launchd agent is needed. (The old launchctl launch
  // agent only spawned an idle detached shell and failed to load on modern
  // macOS with "Load failed: 5".)

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

  // Start the process reaper and the mDNSResponder proxy before sealing the
  // sandbox. The proxy binds its listening socket now (while writes are still
  // unrestricted); the sandbox rules below then permit it to serve requests
  // and reach the host daemon.
  reaper_init();
  char mdns_path[MAX_PATH_LEN];
  mdns_proxy_socket_path(container_root, mdns_path, sizeof(mdns_path));
  mdns_proxy_start(container_root);

  char sandbox_profile[4096];
  snprintf(
      sandbox_profile, sizeof(sandbox_profile),
      "(version 1)"
      "(deny default)"
      "(allow process-fork)"
      "(allow file-read*)"
      // TTY ioctls (TIOCGETA/TIOCSETA/TIOCGWINSZ) are how isatty(),
      // tcgetattr() and tcsetattr() actually talk to the terminal. Under
      // (deny default) the sandbox blocks these ioctls, so inside the box
      // isatty() returns false and readline cannot switch the terminal into
      // raw mode -- arrow keys then leak raw escape bytes ("^[[D") into the
      // prompt and corrupt commands. Allowing file-ioctl restores real
      // interactive line editing (history, arrows, Home/End, Ctrl-keys).
      "(allow file-ioctl)"
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
      // mDNSResponder proxy: bind/serve the in-container socket and reach
      // the host daemon so DNS / Bonjour resolution works inside the box.
      "(allow network-bind (literal \"%s\"))"
      "(allow network-inbound (literal \"%s\"))"
      "(allow network-outbound (literal \"%s\"))"
      "(allow network-outbound (literal \"/var/run/mDNSResponder\"))"
      "(allow network-outbound (literal \"/private/var/run/mDNSResponder\"))"
      // The modern system resolver reaches mDNSResponder over these mach
      // services (not the UNIX socket), so allow them or getaddrinfo / curl /
      // dig DNS fails inside the sandbox.
      "(allow mach-lookup (global-name \"com.apple.dnssd.service\"))"
      "(allow mach-lookup (global-name \"com.apple.mDNSResponder.control\"))"
      "(allow mach-lookup (global-name \"com.apple.mDNSResponder\"))"
      "(allow process-exec (subpath \"/usr\"))"
      "(deny process-exec (subpath \"/usr/local\"))"
      "(allow process-exec (subpath \"/Applications/Xcode.app\"))"
      "(allow process-exec (subpath \"/bin\"))"
      "(allow process-exec (subpath \"/bin\"))"
      "(allow process-exec (subpath \"/sbin\"))"
      "(allow process-exec (subpath \"/dev\"))"
      "(allow process-exec (subpath \"%s\"))",
      container_root, container_root, bin_file_path, shared_mount_point,
      shared_mount_point, mdns_path, mdns_path, mdns_path, container_root);

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
  // Input editing (arrows, history, Home/End/Delete, Ctrl-keys, UTF-8) is
  // handled by GNU readline below. Keep the terminal in normal cooked mode
  // between prompts; readline switches to raw mode only while editing a line
  // and restores cooked mode on return, so spawned commands run normally.
  set_terminal_canonical_mode();

  if (container_log_init(container_root) != 0) {
    perror("Failed to open container log");
  }
  container_log(LOG_INFO, "lifecycle",
                "container started (name=%s vlan=%d cpu_prio=%d "
                "mem_soft=%ld mem_hard=%ld)",
                config.name, config.vlan_id, config.cpu_priority,
                config.memory_soft_limit, config.memory_hard_limit);

  pthread_t logger;
  pthread_create(&logger, NULL, logger_thread, &config);
  int network_thread_active = 1;

  while (1) {
    if (should_exit) {
      break;
    }

    check_scheduled_tasks(container_root);

    char *input_line = readline("> ");
    if (input_line == NULL) { // Ctrl-D / EOF: leave the container shell
      goto exit_loop;
    }
    strncpy(command, input_line, MAX_COMMAND_LEN - 1);
    command[MAX_COMMAND_LEN - 1] = '\0';
    free(input_line);

    if (command[0] == '\0') {
      continue; // blank line: just redraw the prompt
    }
    add_history(command);
    log_command_exec(command);

    if (strcmp(command, "exit") == 0)
      goto exit_loop;
    if (strcmp(command, "debug") == 0) {
      enter_debug_mode();
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
    } else if (strncmp(command, "br ", 3) == 0) { // Note the space after 'br'
      char *cmd = command + 3;                    // Skip "br " prefix
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
  }

exit_loop:
  printf("Container terminated.\n");
  container_log(LOG_INFO, "lifecycle", "container terminated");
  // Terminate every process the container spawned, then tear down the proxy.
  reaper_shutdown();
  mdns_proxy_stop();
  // Clean up the threads
  pthread_cancel(network_thread);
  pthread_join(network_thread, NULL);
  pthread_cancel(logger);
  pthread_join(logger, NULL);
  container_log_close();
  // Cleanup container state
  for (int i = 0; i < container_state.num_env_vars; i++) {
    free(container_state.environment_variables[i]);
  }
  free(container_state.environment_variables);
  exit(0);

stop_loop:
  set_terminal_canonical_mode();
  printf("Container stopped.\n");
  container_log(LOG_INFO, "lifecycle", "container stopped (state saved)");
  reaper_shutdown();
  mdns_proxy_stop();
  pthread_cancel(network_thread);
  pthread_join(network_thread, NULL);
  pthread_cancel(logger);
  pthread_join(logger, NULL);
  container_log_close();
  // Preserve the environment variables
  for (int i = 0; i < container_state.num_env_vars; i++) {
    setenv(container_state.environment_variables[i], NULL, 1);
  }
}

// Creates an isolated_environment without the vlan network or ports.
void ocreate_isolated_environment(FILE *bin_file, const char *bin_file_path) {
  signal(SIGTERM, handle_signal);
  signal(SIGINT, handle_signal);
  signal(SIGSEGV, handle_signal);
  signal(SIGBUS, handle_signal);
  signal(SIGILL, handle_signal);
  signal(SIGFPE, handle_signal);
  signal(SIGABRT, handle_signal);

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

  // The interactive container runs in this process after dropping privileges
  // below, so no separate launchd agent is needed. (The old launchctl launch
  // agent only spawned an idle detached shell and failed to load on modern
  // macOS with "Load failed: 5".)

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

  // Start the process reaper and the mDNSResponder proxy before sealing the
  // sandbox.
  reaper_init();
  char mdns_path[MAX_PATH_LEN];
  mdns_proxy_socket_path(container_root, mdns_path, sizeof(mdns_path));
  mdns_proxy_start(container_root);

  char sandbox_profile[4096];
  snprintf(
      sandbox_profile, sizeof(sandbox_profile),
      "(version 1)"
      "(deny default)"
      "(allow process-fork)"
      "(allow file-read*)"
      // TTY ioctls (TIOCGETA/TIOCSETA/TIOCGWINSZ) are how isatty(),
      // tcgetattr() and tcsetattr() actually talk to the terminal. Under
      // (deny default) the sandbox blocks these ioctls, so inside the box
      // isatty() returns false and readline cannot switch the terminal into
      // raw mode -- arrow keys then leak raw escape bytes ("^[[D") into the
      // prompt and corrupt commands. Allowing file-ioctl restores real
      // interactive line editing (history, arrows, Home/End, Ctrl-keys).
      "(allow file-ioctl)"
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
      // mDNSResponder proxy: bind/serve the in-container socket and reach
      // the host daemon so DNS / Bonjour resolution works inside the box.
      "(allow network-bind (literal \"%s\"))"
      "(allow network-inbound (literal \"%s\"))"
      "(allow network-outbound (literal \"%s\"))"
      "(allow network-outbound (literal \"/var/run/mDNSResponder\"))"
      "(allow network-outbound (literal \"/private/var/run/mDNSResponder\"))"
      // The modern system resolver reaches mDNSResponder over these mach
      // services (not the UNIX socket), so allow them or getaddrinfo / curl /
      // dig DNS fails inside the sandbox.
      "(allow mach-lookup (global-name \"com.apple.dnssd.service\"))"
      "(allow mach-lookup (global-name \"com.apple.mDNSResponder.control\"))"
      "(allow mach-lookup (global-name \"com.apple.mDNSResponder\"))"
      "(allow process-exec (subpath \"/usr\"))"
      "(deny process-exec (subpath \"/usr/local\"))"
      "(allow process-exec (subpath \"/Applications/Xcode.app\"))"
      "(allow process-exec (subpath \"/bin\"))"
      "(allow process-exec (subpath \"/bin\"))"
      "(allow process-exec (subpath \"/sbin\"))"
      "(allow process-exec (subpath \"/dev\"))"
      "(allow process-exec (subpath \"%s\"))",
      container_root, container_root, bin_file_path, shared_mount_point,
      shared_mount_point, mdns_path, mdns_path, mdns_path, container_root);

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
  // See note above: readline owns line editing; keep cooked mode between
  // prompts.
  set_terminal_canonical_mode();

  if (container_log_init(container_root) != 0) {
    perror("Failed to open container log");
  }
  container_log(LOG_INFO, "lifecycle",
                "container resumed (name=%s vlan=%d cpu_prio=%d)", config.name,
                config.vlan_id, config.cpu_priority);

  pthread_t logger;
  pthread_create(&logger, NULL, logger_thread, &config);

  while (1) {
    if (should_exit) {
      break;
    }

    check_scheduled_tasks(container_root);

    char *input_line = readline("> ");
    if (input_line == NULL) { // Ctrl-D / EOF: leave the container shell
      goto exit_loop;
    }
    strncpy(command, input_line, MAX_COMMAND_LEN - 1);
    command[MAX_COMMAND_LEN - 1] = '\0';
    free(input_line);

    if (command[0] == '\0') {
      continue; // blank line: just redraw the prompt
    }
    add_history(command);
    log_command_exec(command);

    if (strcmp(command, "exit") == 0)
      goto exit_loop;
    if (strcmp(command, "debug") == 0) {
      enter_debug_mode();
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
    } else if (strncmp(command, "br ", 3) == 0) { // Note the space after 'br'
      char *cmd = command + 3;                    // Skip "br " prefix
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
  }

exit_loop:
  set_terminal_canonical_mode();
  printf("Container terminated.\n");
  container_log(LOG_INFO, "lifecycle", "container terminated");

  reaper_shutdown();
  mdns_proxy_stop();
  pthread_cancel(logger);
  pthread_join(logger, NULL);
  container_log_close();

  for (int i = 0; i < container_state.num_env_vars; i++) {
    free(container_state.environment_variables[i]);
  }
  free(container_state.environment_variables);
  exit(0);

stop_loop:
  set_terminal_canonical_mode();
  printf("Container stopped.\n");
  container_log(LOG_INFO, "lifecycle", "container stopped (state saved)");
  reaper_shutdown();
  mdns_proxy_stop();
  pthread_cancel(logger);
  pthread_join(logger, NULL);
  container_log_close();

  // Preserve the environment variables
  for (int i = 0; i < container_state.num_env_vars; i++) {
    setenv(container_state.environment_variables[i], NULL, 1);
  }
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
