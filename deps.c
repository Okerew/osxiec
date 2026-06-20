#include "osxiec.h"
#include <dirent.h>
#include <errno.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

const char *get_homebrew_prefix() {
#if defined(__APPLE__) && defined(__aarch64__)
  return "/opt/homebrew";
#else
  return "/usr/local";
#endif
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

  for (int i = 0; i < num_core_dirs; i++) {
    if (file_exists(core_system_dirs[i])) {
      printf("  Linking system directory: %s\n", core_system_dirs[i]);

      char container_path[PATH_MAX];
      snprintf(container_path, sizeof(container_path), "%s%s", container_root,
               core_system_dirs[i]);

      char *container_path_copy = strdup(container_path);
      char *parent_dir = dirname(container_path_copy);
      if (mkdir(parent_dir, 0755) != 0 && errno != EEXIST) {
        printf("  Error: Failed to create parent directory for %s: %s\n",
               container_path, strerror(errno));
        free(container_path_copy);
        continue;
      }
      free(container_path_copy);

      // Replace a stale symlink so the target is always correct; a real file
      // or directory left by extraction is treated as already present.
      struct stat st;
      if (lstat(container_path, &st) == 0 && S_ISLNK(st.st_mode)) {
        unlink(container_path);
      }

      if (symlink(core_system_dirs[i], container_path) == 0) {
        linked_count++;
      } else if (errno == EEXIST) {
        // Already provided by the container image; nothing to do.
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
