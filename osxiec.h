#ifndef OSXIEC_H
#define OSXIEC_H
#include <pthread.h>
#include <stdio.h>
#include <sys/_types/_gid_t.h>
#include <sys/_types/_uid_t.h>
#include <sys/types.h>
#include <time.h>

#define MAX_PATH_LEN 256
#define MAX_SECRETS 64

/* Per-network bridge interfaces are named bridge(OSXIEC_BRIDGE_BASE + id) so
 * they never clash with the system Thunderbolt bridge0. 802.1Q vlan
 * interfaces can't bind to Wi-Fi on macOS (SIOCSETVLAN is silently ignored),
 * so bridges carry the container subnet instead. */
#define OSXIEC_BRIDGE_BASE 1000
#define MAX_VAR_LEN 1024
#define MAX_COMMAND_LEN 1024
#define MAX_DEPS 256
#define VERSION "v1.1.1"

typedef struct {
  char name[MAX_PATH_LEN];
  size_t size;
  char *data;
} File;

#define MAX_CLIENTS 15

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

typedef struct {
  char name[MAX_PATH_LEN];
  char data[4096];
  char audit_data[2048];
  char outdated_data[1024];
} BrewInfo;

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

void execute_command(const char *command, const char *container_root);
void containerize_directory_with_bin_file(const char *dir_path,
                                          const char *input_bin_file,
                                          const char *output_file,
                                          const char *start_config_file,
                                          const char *container_config_file);
void containerize_directory(const char *dir_path, const char *output_file,
                            const char *start_config_file,
                            const char *container_config_file);
void read_config_file(const char *filename, ContainerConfig *config);
void extract_container(const char *osxiec_file, const char *output_dir);
void security_scan(const char *bin_file);
ContainerNetwork load_container_network(const char *name);
void deploy_container(const char *config_file, int deploy_port);
void apply_resource_limits(const ContainerConfig *config);
void *monitor_memory_usage(void *arg);
void setup_pf_rules(ContainerNetwork *network);
void create_and_save_container_network(const char *name, int vlan_id,
                                       const char *allowed_ip);
void remove_container_network(const char *name);
void remove_pf_configs(int vlan_number);
void start_auto_scaling(ContainerConfig *config);
void handle_client(int client_socket, const char *container_root);
void start_network_listener(const char *container_root);
void create_isolated_environment(FILE *bin_file, const char *bin_file_path,
                                 ContainerNetwork *network);
void ocreate_isolated_environment(FILE *bin_file, const char *bin_file_path);
static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb,
                                  void *userp);
void search(const char *term);
void download_file(const char *file_name);
void upload_file(const char *filename, const char *username,
                 const char *password, const char *description);
void convert_to_docker(const char *osxiec_file, const char *output_dir,
                       const char *base_image, const char *custom_dockerfile);
void clean_container_dmgs();
void convert_to_oci(const char *osxiec_file, const char *output_dir,
                    const char *arch, const char *author, const char *created);
char *find_latest_bin_file(const char *volume_name);
int copy_file(const char *source, const char *destination_folder,
              const char *new_file_name);
size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp);
char *fetch_latest_version(void);
int compare_versions(const char *v1, const char *v2);
int add_plugin(const char *plugin_source);
void create_directory_if_needed(const char *path);
void handle_signal(int sig);
void *logger_thread(void *arg);
void signal_handler();
void navigate_history(char *command, int *command_index, int *cursor_pos,
                      int direction);
void add_to_history(const char *command);
void clear_line();
void move_cursor_right(int n);
void move_cursor_left(int n);
void set_terminal_canonical_mode();
void set_terminal_raw_mode();
void detach_container_images(const char *volume_name);
void print_current_resource_usage(ContainerConfig *config);
void start_auto_scaling(ContainerConfig *config);
double get_cpu_usage();
void create_directories(const char *file_path);
void create_shared_folder();
void handle_script_file(const char *filename);
void handle_script_command(const char *script_content);
void scale_container_resources(long memory_soft_limit, long memory_hard_limit,
                               int cpu_priority);
void enable_container_communication(ContainerNetwork *network);
void setup_network_isolation(ContainerConfig *config,
                             ContainerNetwork *network);
char *get_ip_address();
void execute_start_config(const char *config_file, const char *container_root);
int is_subpath(const char *path, const char *base);
int handle_debug_command(char *command);
void debug_prompt_loop(void);
void enter_debug_mode(void);
void print_container_state();
void update_container_state();
void broadcast_command_to_network(const char *network_name, const char *command,
                                  int port);
int copy_volume_to_directory(const char *volume_name, const char *target_dir);
void update_container_config(const char *container_file,
                             const char *new_config_file);
int remove_plugin(const char *plugin_name);
int link_system_directories(const char *container_root);
int process_dependencies_recursive(const char *dep_name,
                                   const char *homebrew_prefix, File *files,
                                   int *file_count, int max_files,
                                   char processed[][MAX_PATH_LEN],
                                   int *processed_count);
int process_dependency(const char *dep_name, const char *homebrew_prefix,
                       File *files, int *file_count, int max_files);
int get_brew_info(const char *package_name, BrewInfo *info);
const char *get_homebrew_prefix();
void analyze_security_findings(const BrewInfo *info);
int parse_brew_dependencies(const char *brew_info_data,
                            char deps[][MAX_PATH_LEN], int max_deps);
int file_exists(const char *path);
int copy_single_file(const char *src_path, const char *dest_path, File *files,
                     int *file_count, int max_files);

int copy_path(const char *src_path, const char *dest_path, File *files,
              int *file_count, int max_files);
int is_base64(const char *str);
void handle_secret_command(const char *args);
void handle_getsecret_command(const char *args);
void save_container_state(FILE *state_file, const ContainerConfig *config,
                          const ContainerState *state);
void clean_container_plists();
void cleanup_all_container_users(void);

/* exec.c */
void *background_command_thread(void *arg);
int start_background_task(const char *command, const char *container_root);
void pause_background_tasks(void);
void unpause_background_tasks(void);
void wait_background_task(int task_id);
void show_background_tasks(void);
void start_network_thread(pthread_t network_thread, int network_thread_active);
void stop_network_thread(pthread_t network_thread, int network_thread_active);
void trace_command(const char *command, const char *container_root);
void trace_background_process(int process_id, const char *container_root);
void handle_attach_interrupt(int sig);
void live_process_inspection(const char *container_root);
void attach_to_background_task(int task_id);
void schedule_command(const char *command, time_t scheduled_time);
void check_scheduled_tasks(char *container_root);
void list_scheduled_tasks(void);
time_t parse_time(const char *time_str);

void *auto_scale_resources(void *arg);
size_t write_data(void *ptr, size_t size, size_t nmemb, FILE *stream);

/* network.c - mDNSResponder socket proxy */
int mdns_proxy_start(const char *container_root);
void mdns_proxy_stop(void);
void mdns_proxy_socket_path(const char *container_root, char *out,
                            size_t outlen);

/* reaper.c - kqueue-based process reaper */
int reaper_init(void);
void reaper_register(pid_t pid, int is_group_leader);
void reaper_shutdown(void);
#endif // OSXIEC_H
