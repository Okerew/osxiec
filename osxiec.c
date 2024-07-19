#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <sandbox.h>
#include <mach/mach.h>
#include <pthread.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <spawn.h>
#include <curl/curl.h>

#define MAX_COMMAND_LEN 1024
#define MAX_DEPENDENCIES 50 // Note this is not used for now as this was my attempt at dependencies but is way to much work for the tradeof, and deleting it would break the code
#define MAX_PATH_LEN 256
#define MAX_FILE_SIZE 1024*1024*1024
#define MAX_LAYERS 20
#define PORT 3000
#define MAX_CLIENTS 5
#define MAX_COMMAND_LEN 1024

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
    char layer_dir[MAX_PATH_LEN];
} Layer;

typedef struct {
    char name[MAX_PATH_LEN];
    int vlan_id;
    int num_containers;
    char container_names[MAX_CLIENTS][MAX_PATH_LEN];
} ContainerNetwork;

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

extern char **environ;

void execute_command(const char *command) {
    if (command == NULL || strlen(command) == 0) {
        fprintf(stderr, "Error: Empty command\n");
        return;
    }

    printf("Executing: %s\n", command);

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

void execute_start_config(const char *config_file) {
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
        execute_command(line);
    }

    fclose(file);
}


void containerize_directory(const char *dir_path, const char *output_file, const char *start_config_file) {
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
    if (start_config_file) {
        strncpy(config.start_config, start_config_file, MAX_PATH_LEN - 1);
        config.start_config[MAX_PATH_LEN - 1] = '\0';
    } else {
        config.start_config[0] = '\0';
    }
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

void add_container_to_network(ContainerNetwork *network, const char *container_name) {
    if (network->num_containers < MAX_CLIENTS) {
        strncpy(network->container_names[network->num_containers], container_name, MAX_PATH_LEN - 1);
        network->num_containers++;
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
        add_container_to_network(network, config->name);

        printf("Setting up bridge network. Container %s on VLAN %d\n", config->name, config->vlan_id);

        char vlan_cmd[256];
        snprintf(vlan_cmd, sizeof(vlan_cmd), "ifconfig vlan%d create vlan %d vlandev en0",
                 config->vlan_id, config->vlan_id);
        system(vlan_cmd);

        snprintf(vlan_cmd, sizeof(vlan_cmd), "ifconfig vlan%d up", config->vlan_id);
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

void create_isolated_environment(FILE *bin_file, const char *bin_file_path, ContainerNetwork *network) {
    ContainerConfig config;
    fread(&config, sizeof(ContainerConfig), 1, bin_file);

    setup_network_isolation(&config, network);
    enable_container_communication(network);

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

    if (config.start_config[0] != '\0') {
        char start_config_path[MAX_PATH_LEN];
        snprintf(start_config_path, sizeof(start_config_path), "%s/%s", container_root, config.start_config);
        execute_start_config(start_config_path);
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

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Unknown command: %s\n"
                        , argv[0]);
        return EXIT_FAILURE;
    }

    if (strcmp(argv[1], "-contain") == 0) {
        if (argc < 4) {
            fprintf(stderr, "Usage for containerize: %s -contain <directory_path> <output_file> [start_config_file]\n", argv[0]);
            return EXIT_FAILURE;
        }
        if (geteuid() != 0) {
            fprintf(stderr, "This program must be run as root. Try using sudo.\n");
            return EXIT_FAILURE;
        }

        const char *start_config_file = (argc > 4) ? argv[4] : NULL;
        containerize_directory(argv[2], argv[3], start_config_file);
        printf("Directory contents containerized into '%s'.\n", argv[3]);
    } else if (strcmp(argv[1], "-execute") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage for execute: %s -execute <bin_file> [-port <port>]\n", argv[0]);
            return EXIT_FAILURE;
        }

        // Parse port if provided
        for (int i = 3; i < argc; i++) {
            if (strcmp(argv[i], "-port") == 0 && i + 1 < argc) {
                port = atoi(argv[i + 1]);
                break;
            }
        }

        FILE *bin_file = fopen(argv[2], "rb");
        if (bin_file == NULL) {
            perror("Error opening binary file");
            return EXIT_FAILURE;
        }

        ContainerNetwork dummy_network = {0};
        create_isolated_environment(bin_file, argv[2], &dummy_network);
        fclose(bin_file);

    } else if (strcmp(argv[1], "-network") == 0 && strcmp(argv[2], "create") == 0) {
        if (argc < 5) {
            fprintf(stderr, "Usage: %s -network create <name> <vlan_id>\n", argv[0]);
            return EXIT_FAILURE;
        }
        create_and_save_container_network(argv[3], atoi(argv[4]));
        ContainerNetwork network = load_container_network(argv[3]);
        setup_pf_rules(&network);
    }
    else if (strcmp(argv[1], "-run") == 0) {
        if (argc < 4) {
            fprintf(stderr, "Usage: %s run <container_file> <network_name> [-port <port>]\n", argv[0]);
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
    } else if (strcmp(argv[1], "--version") == 0) {
        printf("Osxiec version 0.2\n");
    } else if (strcmp(argv[1], "-pull") == 0) {
        if (argc != 3) {
            printf("Usage: %s pull <file_name>\n", argv[0]);
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
    } else if (strcmp(argv[1], "-help") == 0) {
        printf("Available commands:\n");
        printf("  -contain <directory_path> <output_file>\n");
        printf("  -execute <directory_path> [-port <port>]\n");
        printf("  -network create <name> <vlan_id>\n");
        printf("  -run <container_file> <network_name> [-port <port>]\n");
        printf("  -pull <file_name>\n");
        printf("  -search <search_term>\n");
        printf("  -upload <filename> <username> <password> <description>\n");
        printf("  --version\n");
        printf("  -help\n");

    } else {
        fprintf(stderr, "Unknown command: %s\n", argv[1]);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
