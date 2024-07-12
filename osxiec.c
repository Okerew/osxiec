#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <sandbox.h>
#include <mach/mach.h>
#include <pthread.h>
#include <netinet/in.h>

#define MAX_COMMAND_LEN 1024
#define MAX_DEPENDENCIES 50 // Note this is not used for now as this was my attempt at dependencies but is way to much work for the tradeof, and deleting it would break the code
#define MAX_PATH_LEN 256
#define MAX_FILE_SIZE 1024*1024*1024
#define MAX_LAYERS 20
#define PORT 3000
#define MAX_CLIENTS 5

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
} ContainerConfig;

typedef struct {
    char layer_dir[MAX_PATH_LEN];
} Layer;

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

    while ((entry = readdir(dir)) != NULL && num_files < MAX_DEPENDENCIES) {
        if (entry->d_type == DT_REG) {  // Check if it is a regular file
            snprintf(file_path, sizeof(file_path), "%s/%s", dir_path, entry->d_name);

            if (stat(file_path, &st) == 0) {
                if (st.st_size > MAX_FILE_SIZE) {
                    fprintf(stderr, "File %s is too large (max %d bytes)\n", entry->d_name, MAX_FILE_SIZE);
                    continue;
                }

                strncpy(files[num_files].name, entry->d_name, MAX_PATH_LEN - 1);
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

void execute_command(const char *command) {
    printf("Executing: %s\n", command);

    pid_t pid = fork();

    if (pid == 0) {
        char *args[MAX_COMMAND_LEN / 2 + 1];
        char *command_copy = strdup(command);
        char *token = strtok(command_copy, " ");
        int i = 0;

        while (token != NULL && i < MAX_COMMAND_LEN / 2) {
            args[i++] = token;
            token = strtok(NULL, " ");
        }
        args[i] = NULL;

        if (execvp(args[0], args) == -1) {
            perror("Error executing command");
        }

        free(command_copy);
        exit(EXIT_FAILURE);
    } else if (pid < 0) {
        // Fork failed
        perror("Fork failed");
    } else {
        // Parent process
        int status;
        if (waitpid(pid, &status, 0) == -1) {
            perror("Error waiting for child process");
        }

        if (WIFEXITED(status)) {
            printf("Child process exited with status %d\n", WEXITSTATUS(status));
        } else if (WIFSIGNALED(status)) {
            printf("Child process terminated by signal %d\n", WTERMSIG(status));
        }
    }
}



void containerize_directory(const char *dir_path, const char *output_file) {
    FILE *bin_file = fopen(output_file, "wb");
    if (bin_file == NULL) {
        perror("Error opening output file");
        exit(EXIT_FAILURE);
    }

    File files[MAX_DEPENDENCIES];
    int num_files;

    // Read files from directory

    ContainerConfig config = {
        .name = "default_container",
        .memory_soft_limit = 384 * 1024 * 1024,  // 384 MB
        .memory_hard_limit = 512 * 1024 * 1024,  // 512 MB
        .cpu_priority = 20,  // Normal priority
        .network_mode = "host",
        .container_uid = 1000,  // Default unprivileged user ID
        .container_gid = 1000   // Default unprivileged group ID
    };
    num_files = read_files(dir_path, files, config.container_uid, config.container_gid);
    if (num_files < 0) {
        fclose(bin_file);
        exit(EXIT_FAILURE);
    }

    fwrite(&config, sizeof(ContainerConfig), 1, bin_file);

    // Read layers from the directory
    Layer layers[MAX_LAYERS];
    int num_layers = 0;
    char layers_dir[MAX_PATH_LEN];
    snprintf(layers_dir, sizeof(layers_dir), "%s/layers", dir_path);

    DIR *dir = opendir(layers_dir);
    if (dir == NULL) {
        perror("Error opening layers directory");
        fclose(bin_file);
        exit(EXIT_FAILURE);
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL && num_layers < MAX_LAYERS) {
        if (entry->d_type == DT_DIR && entry->d_name[0] != '.') {
            snprintf(layers[num_layers].layer_dir, sizeof(layers[num_layers].layer_dir), "%s/%s", layers_dir, entry->d_name);
            num_layers++;
        }
    }
    closedir(dir);

    // Write number of layers
    fwrite(&num_layers, sizeof(int), 1, bin_file);

    // Write each layer directory to the binary file
    for (int i = 0; i < num_layers; i++) {
        fwrite(layers[i].layer_dir, sizeof(char), MAX_PATH_LEN, bin_file);
    }

    // Write number of files to the binary file
    fwrite(&num_files, sizeof(int), 1, bin_file);

    // Write each file to the binary file
    for (int i = 0; i < num_files; i++) {
        fwrite(files[i].name, sizeof(char), MAX_PATH_LEN, bin_file);
        fwrite(&files[i].size, sizeof(size_t), 1, bin_file);
        fwrite(files[i].data, 1, files[i].size, bin_file);
        free(files[i].data);
    }

    fclose(bin_file);
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

void setup_network_isolation(const char *network_mode) {
    // Note this is very basic
    if (strcmp(network_mode, "host") == 0) {
        printf("Using host network mode\n");
    } else if (strcmp(network_mode, "none") == 0) {
        printf("Network isolation not fully implemented on macOS\n");
    } else {
        printf("Custom network modes not supported on macOS\n");
    }
}


void apply_layer(const char *layer_dir, const char *target_dir) {
    char command[MAX_COMMAND_LEN];
    snprintf(command, sizeof(command), "cp -r %s/* %s", layer_dir, target_dir);
    execute_command(command);
}

void handle_client(int client_socket) {
    char command[MAX_COMMAND_LEN];
    ssize_t bytes_received;

    while ((bytes_received = recv(client_socket, command, sizeof(command) - 1, 0)) > 0) {
        command[bytes_received] = '\0';

        if (strcmp(command, "exit") == 0) {
            break;
        }

        // Execute the command
        execute_command(command);

        // Send a response back to the client
        const char *response = "Command executed.\n";
        send(client_socket, response, strlen(response), 0);
    }

    close(client_socket);
}

void start_network_listener() {
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
        handle_client(client_socket);
    }
}



void create_isolated_environment(FILE *bin_file, const char *bin_file_path) {
    ContainerConfig config;
    fread(&config, sizeof(ContainerConfig), 1, bin_file);

    int num_layers;
    fread(&num_layers, sizeof(int), 1, bin_file);

    Layer layers[MAX_LAYERS];
    for (int i = 0; i < num_layers; i++) {
        fread(layers[i].layer_dir, sizeof(char), MAX_PATH_LEN, bin_file);
    }

    int num_files;
    fread(&num_files, sizeof(int), 1, bin_file);

    // Create and mount disk image for file system isolation
    char disk_image_path[MAX_PATH_LEN];
    snprintf(disk_image_path, sizeof(disk_image_path), "/tmp/container_disk_%d.dmg", getpid());

    char create_disk_command[MAX_COMMAND_LEN];
    snprintf(create_disk_command, sizeof(create_disk_command),
             "hdiutil create -size 1g -fs HFS+ -volname Container %s", disk_image_path);
    system(create_disk_command);

    // Ensure the disk image has correct permissions
    chmod(disk_image_path, 0644);  // rw-r--r--

    char mount_command[MAX_COMMAND_LEN];
    snprintf(mount_command, sizeof(mount_command), "hdiutil attach %s", disk_image_path);
    system(mount_command);

    // Use /Volumes/Container as the new container root
    char container_root[] = "/Volumes/Container";

    // Apply layers
    for (int i = 0; i < num_layers; i++) {
        apply_layer(layers[i].layer_dir, container_root);
    }

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

        FILE *out_file = fopen(file_path, "wb");
        if (out_file == NULL) {
            perror("Error creating file in container");
            exit(EXIT_FAILURE);
        }

        fwrite(file.data, 1, file.size, out_file);
        fclose(out_file);
        free(file.data);

        // Make the file executable and writable
        chmod(file_path, 0755);
    }

    // Make the container root directory writable
    chmod(container_root, 0755);

    // Change to container root
    if (chdir(container_root) != 0) {
        perror("Failed to change to container root directory");
        exit(1);
    }

    // Set group ID first
    if (setgid(config.container_gid) != 0) {
        perror("Failed to set group ID");
        exit(1);
    }

    // Set user ID
    if (setuid(config.container_uid) != 0) {
        perror("Failed to set user ID");
        exit(1);
    }

    // Apply resource limits
    apply_resource_limits(&config);

    // Setup network isolation
    setup_network_isolation(config.network_mode);

    // Setup sandbox profile
    char sandbox_profile[1024];
    snprintf(sandbox_profile, sizeof(sandbox_profile),
             "(version 1)\
             (deny default)\
             (allow process-exec)\
             (allow process-fork)\
             (allow file-read*)\
             (allow file-write* (subpath \"%s\"))\
             (allow file-read* (subpath \"%s\"))\
             (allow file-read* (literal \"%s\"))\
             (allow file-read* (subpath \"/usr/lib\"))\
             (allow file-read* (subpath \"/usr/bin\"))\
             (allow file-read* (subpath \"/bin\"))\
             (allow file-read* (subpath \"/System\"))\
             (allow sysctl-read)\
             (allow mach-lookup)\
             (allow network-outbound (remote ip))\
             (allow network-inbound (local ip))",
             container_root, container_root, bin_file_path);

    char *error;
    if (sandbox_init(sandbox_profile, 0, &error) != 0) {
        fprintf(stderr, "sandbox_init failed: %s\n", error);
        sandbox_free_error(error);
        exit(1);
    }

    printf("\n=== Container Terminal ===\n");
    printf("Enter commands (type 'exit' to quit):\n");

    // Start the network listener in a separate thread
    pthread_t network_thread;
    if (pthread_create(&network_thread, NULL, (void *(*)(void *))start_network_listener, NULL) != 0) {
        perror("Failed to create network listener thread");
    }

    char command[MAX_COMMAND_LEN];
    while (1) {
        printf("> ");
        fflush(stdout);

        if (fgets(command, sizeof(command), stdin) == NULL) break;
        command[strcspn(command, "\n")] = '\0';

        if (strcmp(command, "exit") == 0) break;

        execute_command(command);
        printf("\n");
    }

    printf("Container terminated.\n");

    // Clean up the network thread
    pthread_cancel(network_thread);
    pthread_join(network_thread, NULL);

    // Unmount and remove the disk image
    char unmount_command[MAX_COMMAND_LEN];
    snprintf(unmount_command, sizeof(unmount_command), "hdiutil detach %s", container_root);
    system(unmount_command);

    char remove_disk_command[MAX_COMMAND_LEN];
    snprintf(remove_disk_command, sizeof(remove_disk_command), "rm %s", disk_image_path);
    system(remove_disk_command);
}


int main(int argc, char *argv[]) {
    // We are not using argc < 3 because then the version command wouldn't work
    if (argc < 2) {
        fprintf(stderr, "Usage: %s -<contain|execute> <directory_path|bin_file> [-port <port>]\n", argv[0]);
        return EXIT_FAILURE;
    }

    if (strcmp(argv[1], "-contain") == 0) {
        if (argc < 4) {
            fprintf(stderr, "Usage for containerize: %s -contain <directory_path> <output_file>\n", argv[0]);
            return EXIT_FAILURE;
        }
        if (geteuid() != 0) {
            fprintf(stderr, "This program must be run as root. Try using sudo.\n");
            return EXIT_FAILURE;
        }

        containerize_directory(argv[2], argv[3]);
        printf("Directory contents containerized into '%s'.\n", argv[3]);
    } else if (strcmp(argv[1], "-execute") == 0) {
        if (argc >= 4 && strcmp(argv[3], "-port") == 0 && argc >= 5) {
            port = atoi(argv[4]);
        }

        FILE *bin_file = fopen(argv[2], "rb");
        if (bin_file == NULL) {
            perror("Error opening binary file");
            return EXIT_FAILURE;
        }
        create_isolated_environment(bin_file, argv[2]);
        fclose(bin_file);

        pthread_t network_thread;
        if (pthread_create(&network_thread, NULL, (void *(*)(void *))start_network_listener, NULL) != 0) {
            perror("Failed to create network listener thread");
        }

        // Wait for network listener thread to finish
        pthread_join(network_thread, NULL);
    } else if (strcmp("--version", argv[1]) == 0) {
        printf("Osxiec version 0.1\n");
    } else {
        fprintf(stderr, "Unknown command: %s\n", argv[1]);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
