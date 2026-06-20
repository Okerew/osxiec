#include "globals/globals.h"
#include "osxiec.h"
#include "osxiec_script/osxiec_script.h"
#include "plugin_manager/plugin_manager.h"
#include <dirent.h>
#include <errno.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

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
        char clone_command[MAX_COMMAND_LEN];
        sprintf(clone_command,
                "git clone --depth 1 --branch %s "
                "https://github.com/Okerew/osxiec.git "
                "osxiec_update",
                latest_version);
        if (system(clone_command) == 0) {
          if (chdir("osxiec_update") != 0) {
            perror("chdir() to 'osxiec_update' failed");
            system("rm -rf osxiec_update");
            free(latest_version);
            return 1;
          }
          if (system("sudo sh install.sh") == 0) {
            printf("Update successful. Please restart osxiec.\n");
            chdir("..");
            system("rm -rf osxiec_update");
          } else {
            printf("Installation failed.\n");
            chdir("..");
            system("rm -rf osxiec_update");
          }
        } else {
          printf("There was some error while updating. \n");
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
  } else {
    fprintf(stderr, "Unknown command: %s\n", argv[1]);
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
