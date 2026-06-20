#include "globals/globals.h"
#include "osxiec.h"
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

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

// Stock macOS /etc/pf.conf, recreated if the file has gone missing (e.g. an
// older `-pfclean` removed it). The com.apple anchor points must be present for
// pf to load, and our anchors are inserted relative to them.
static const char *DEFAULT_PF_CONF =
    "#\n"
    "# Default PF configuration file.\n"
    "#\n"
    "# See pf.conf(5) for syntax.\n"
    "#\n"
    "\n"
    "#\n"
    "# com.apple anchor point\n"
    "#\n"
    "scrub-anchor \"com.apple/*\"\n"
    "nat-anchor \"com.apple/*\"\n"
    "rdr-anchor \"com.apple/*\"\n"
    "dummynet-anchor \"com.apple/*\"\n"
    "anchor \"com.apple/*\"\n"
    "load anchor \"com.apple\" from \"/etc/pf.anchors/com.apple\"\n";

// Reference the osxiec pf anchors from /etc/pf.conf in the correct sections -
// nat-anchor in the translation section, anchor in the filtering section - and
// strip any stray include/pass rules that older osxiec versions appended
// directly to the main ruleset (those landed after the filter anchors and
// triggered the "Rules must be in order" error). Idempotent.
static void ensure_osxiec_pf_anchors(void) {
  FILE *in = fopen("/etc/pf.conf", "r");
  if (in == NULL) {
    // The main config is missing; recreate the stock ruleset so pf and our
    // anchors work again.
    FILE *def = fopen("/etc/pf.conf", "w");
    if (def == NULL) {
      perror("Failed to create /etc/pf.conf");
      return;
    }
    fputs(DEFAULT_PF_CONF, def);
    fclose(def);
    in = fopen("/etc/pf.conf", "r");
    if (in == NULL) {
      perror("Failed to open /etc/pf.conf");
      return;
    }
  }

  static char lines[1024][512];
  int n = 0, have_nat = 0, have_anchor = 0;
  while (n < 1024 && fgets(lines[n], sizeof(lines[n]), in)) {
    if (strstr(lines[n], "nat-anchor \"osxiec/*\"")) {
      have_nat = 1;
    }
    if (strncmp(lines[n], "anchor \"osxiec/*\"", 16) == 0) {
      have_anchor = 1;
    }
    n++;
  }
  fclose(in);

  FILE *out = fopen("/etc/pf.conf", "w");
  if (out == NULL) {
    perror("Failed to update /etc/pf.conf");
    return;
  }
  for (int i = 0; i < n; i++) {
    if (strstr(lines[i], "include \"/etc/pf.vlan")) {
      continue; // drop stray include of a VLAN file (contains a nat rule)
    }
    if (strncmp(lines[i], "pass on vlan", 12) == 0) {
      continue; // drop stray bare pass rules (now live in the anchor)
    }
    fputs(lines[i], out);
    if (!have_nat && strncmp(lines[i], "nat-anchor \"com.apple/*\"", 24) == 0) {
      fputs("nat-anchor \"osxiec/*\"\n", out);
    }
    if (!have_anchor && strncmp(lines[i], "anchor \"com.apple/*\"", 20) == 0) {
      fputs("anchor \"osxiec/*\"\n", out);
    }
  }
  fclose(out);
}

void setup_pf_rules(ContainerNetwork *network) {
  char *ip_address = get_ip_address();
  if (ip_address == NULL) {
    fprintf(stderr, "Failed to get IP address\n");
    return;
  }

  // Create the VLAN interface only if it does not already exist (avoids the
  // "SIOCSETVLAN: Resource busy" error on re-runs), then always (re)assign its
  // address as a separate step.
  char ip_cmd[256];
  snprintf(ip_cmd, sizeof(ip_cmd),
           "ifconfig vlan%d >/dev/null 2>&1 || "
           "ifconfig vlan%d create vlan %d vlandev en0",
           network->vlan_id, network->vlan_id, network->vlan_id);
  system(ip_cmd);
  snprintf(ip_cmd, sizeof(ip_cmd), "ifconfig vlan%d inet %s/24 up",
           network->vlan_id, ip_address);
  system(ip_cmd);

  // Write this VLAN's ruleset. It is internally correctly ordered (translation
  // before filtering) and is loaded into its own sub-anchor, so it never
  // disturbs the ordering of the main ruleset.
  char vlan_rules_file[64];
  snprintf(vlan_rules_file, sizeof(vlan_rules_file), "/etc/pf.vlan%d.conf",
           network->vlan_id);

  FILE *vlan_pf_conf = fopen(vlan_rules_file, "w");
  if (vlan_pf_conf == NULL) {
    perror("Failed to create VLAN rules file");
    free(ip_address);
    return;
  }
  fprintf(vlan_pf_conf,
          "# osxiec VLAN %d rules\n"
          "nat on en0 from %s/24 to any -> (en0)\n"
          "pass on vlan%d all\n"
          "pass in on vlan%d all\n"
          "pass out on vlan%d all\n",
          network->vlan_id, ip_address, network->vlan_id, network->vlan_id,
          network->vlan_id);
  fclose(vlan_pf_conf);

  // Reference the osxiec anchors from the main ruleset.
  ensure_osxiec_pf_anchors();

  char anchor[64];
  snprintf(anchor, sizeof(anchor), "osxiec/vlan%d", network->vlan_id);

  // Validate both the main ruleset and this VLAN's anchor before applying, so a
  // syntax problem can never take down the host firewall.
  char cmd[256];
  if (system("pfctl -nf /etc/pf.conf") != 0) {
    fprintf(stderr, "pf: /etc/pf.conf failed validation; not reloading\n");
    free(ip_address);
    return;
  }
  snprintf(cmd, sizeof(cmd), "pfctl -a %s -nf %s", anchor, vlan_rules_file);
  if (system(cmd) != 0) {
    fprintf(stderr, "pf: VLAN %d ruleset failed validation; not loaded\n",
            network->vlan_id);
    free(ip_address);
    return;
  }

  // Reload the main ruleset (to pick up the anchor references), load this
  // VLAN's rules into its sub-anchor, and enable pf.
  system("pfctl -f /etc/pf.conf");
  snprintf(cmd, sizeof(cmd), "pfctl -a %s -f %s", anchor, vlan_rules_file);
  system(cmd);
  system("pfctl -e 2>/dev/null");

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

    // Create the VLAN interface only if it does not already exist (avoids the
    // "SIOCSETVLAN: Resource busy" error when the interface is left over from a
    // previous run), then always (re)assign its address as a separate step.
    char vlan_cmd[256];
    snprintf(vlan_cmd, sizeof(vlan_cmd),
             "ifconfig vlan%d >/dev/null 2>&1 || "
             "ifconfig vlan%d create vlan %d vlandev en0",
             config->vlan_id, config->vlan_id, config->vlan_id);
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
  // The pass rules for this VLAN already live in its ruleset file; (re)load
  // them into the per-VLAN anchor instead of appending to the main ruleset
  // (which previously accumulated duplicate rules and broke rule ordering).
  char vlan_rules_file[64];
  snprintf(vlan_rules_file, sizeof(vlan_rules_file), "/etc/pf.vlan%d.conf",
           network->vlan_id);
  if (access(vlan_rules_file, R_OK) != 0) {
    return; // no ruleset for this VLAN yet (created by setup_pf_rules)
  }

  ensure_osxiec_pf_anchors();

  char cmd[256];
  snprintf(cmd, sizeof(cmd), "pfctl -a osxiec/vlan%d -nf %s", network->vlan_id,
           vlan_rules_file);
  if (system(cmd) != 0) {
    fprintf(stderr, "pf: VLAN %d ruleset failed validation; not loaded\n",
            network->vlan_id);
    return;
  }

  system("pfctl -f /etc/pf.conf");
  snprintf(cmd, sizeof(cmd), "pfctl -a osxiec/vlan%d -f %s", network->vlan_id,
           vlan_rules_file);
  system(cmd);
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

  // Create socket file descriptor. This function runs on its own thread, so a
  // failure here must NOT exit() - that would tear down the whole container.
  // Log, give up on the listener, and let the container keep running.
  if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("socket failed");
    return;
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
  // Clean up only what osxiec created for this VLAN. The host's main ruleset
  // (/etc/pf.conf) is left intact - the osxiec anchor references there are
  // shared across VLANs and harmless when empty, and deleting /etc/pf.conf
  // would wipe the system firewall configuration.
  char vlan_conf_path[256];
  snprintf(vlan_conf_path, sizeof(vlan_conf_path), "/etc/pf.vlan%d.conf",
           vlan_number);

  // Flush this VLAN's rules from its dedicated sub-anchor.
  char cmd[128];
  snprintf(cmd, sizeof(cmd), "pfctl -a osxiec/vlan%d -F all 2>/dev/null",
           vlan_number);
  system(cmd);

  // Remove this VLAN's ruleset file.
  if (remove(vlan_conf_path) == 0) {
    printf("Removed: %s\n", vlan_conf_path);
  } else if (errno == ENOENT) {
    printf("No pf ruleset file for VLAN %d (nothing to remove)\n", vlan_number);
  } else {
    perror("Error removing pf.vlanX.conf");
  }

  printf("Cleaned pf rules for VLAN %d (left /etc/pf.conf intact)\n",
         vlan_number);
}

// ---------------------------------------------------------------------------
// mDNSResponder socket proxy
//
// The sandbox profile applied to the container denies everything by default,
// so processes inside it cannot reach the host's /var/run/mDNSResponder UNIX
// socket and DNS / Bonjour resolution fails. This proxy listens on a socket
// inside the container's filesystem (<container_root>/var/run/mDNSResponder)
// and relays each connection to the real host daemon. Container processes are
// pointed at it through the DNSSD_UDS_PATH environment variable, which the
// dns_sd client library honours instead of the compiled-in default path.
//
// The dns_sd UDS protocol passes file descriptors between client and daemon
// using SCM_RIGHTS ancillary messages, so the relay forwards both the payload
// bytes and any descriptors; a byte-only relay would drop the passed fds and
// silently break DNSServiceProcessResult() callbacks.
// ---------------------------------------------------------------------------

#define MDNS_HOST_SOCKET_PATH "/var/run/mDNSResponder"
#define MDNS_MAX_PASSED_FDS 8

static volatile sig_atomic_t mdns_proxy_running = 0;
static int mdns_listen_fd = -1;
static char mdns_proxy_path[108]; // sized to sun_path

void mdns_proxy_socket_path(const char *container_root, char *out,
                            size_t outlen) {
  snprintf(out, outlen, "%s/var/run/mDNSResponder", container_root);
}

// Relay one message from `from` to `to`, forwarding any SCM_RIGHTS file
// descriptors. Returns 1 if a message was relayed, 0 on clean EOF, -1 on
// error.
static int mdns_relay_once(int from, int to) {
  char databuf[8192];
  char ctrlbuf[CMSG_SPACE(sizeof(int) * MDNS_MAX_PASSED_FDS)];

  struct iovec iov = {.iov_base = databuf, .iov_len = sizeof(databuf)};
  struct msghdr msg;
  memset(&msg, 0, sizeof(msg));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = ctrlbuf;
  msg.msg_controllen = sizeof(ctrlbuf);

  ssize_t n = recvmsg(from, &msg, 0);
  if (n == 0) {
    return 0; // peer closed the connection
  }
  if (n < 0) {
    return (errno == EINTR) ? 1 : -1;
  }

  // Collect any descriptors the sender passed to us.
  int fds[MDNS_MAX_PASSED_FDS];
  int nfds = 0;
  for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
       cmsg = CMSG_NXTHDR(&msg, cmsg)) {
    if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
      int count = (int)((cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int));
      for (int i = 0; i < count && nfds < MDNS_MAX_PASSED_FDS; i++) {
        int fd;
        memcpy(&fd, CMSG_DATA(cmsg) + i * sizeof(int), sizeof(int));
        fds[nfds++] = fd;
      }
    }
  }

  // Re-attach the descriptors (if any) to the forwarded payload.
  struct iovec oiov = {.iov_base = databuf, .iov_len = (size_t)n};
  struct msghdr omsg;
  memset(&omsg, 0, sizeof(omsg));
  omsg.msg_iov = &oiov;
  omsg.msg_iovlen = 1;

  char octrl[CMSG_SPACE(sizeof(int) * MDNS_MAX_PASSED_FDS)];
  if (nfds > 0) {
    memset(octrl, 0, sizeof(octrl));
    omsg.msg_control = octrl;
    omsg.msg_controllen = CMSG_SPACE(sizeof(int) * nfds);
    struct cmsghdr *ocmsg = CMSG_FIRSTHDR(&omsg);
    ocmsg->cmsg_level = SOL_SOCKET;
    ocmsg->cmsg_type = SCM_RIGHTS;
    ocmsg->cmsg_len = CMSG_LEN(sizeof(int) * nfds);
    memcpy(CMSG_DATA(ocmsg), fds, sizeof(int) * nfds);
    omsg.msg_controllen = ocmsg->cmsg_len;
  }

  ssize_t w;
  do {
    w = sendmsg(to, &omsg, 0);
  } while (w < 0 && errno == EINTR);

  // sendmsg duplicated the descriptors into the peer; release our copies.
  for (int i = 0; i < nfds; i++) {
    close(fds[i]);
  }

  if (w < 0) {
    return -1;
  }

  // Stream sockets may have sent only part of the payload (ancillary data is
  // delivered with this first chunk); push out whatever remains.
  size_t off = (size_t)w;
  while (off < (size_t)n) {
    ssize_t s = send(to, databuf + off, (size_t)n - off, 0);
    if (s < 0) {
      if (errno == EINTR) {
        continue;
      }
      return -1;
    }
    off += (size_t)s;
  }

  return 1;
}

// Handles a single container-side connection by opening its own connection to
// the host mDNSResponder and pumping data both ways.
static void *mdns_conn_thread(void *arg) {
  int client_fd = (int)(intptr_t)arg;

  int host_fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (host_fd == -1) {
    close(client_fd);
    return NULL;
  }

  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, MDNS_HOST_SOCKET_PATH, sizeof(addr.sun_path) - 1);
  if (connect(host_fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
    perror("mdns proxy: connect to host mDNSResponder");
    close(host_fd);
    close(client_fd);
    return NULL;
  }

  struct pollfd pfds[2];
  pfds[0].fd = client_fd;
  pfds[1].fd = host_fd;

  int done = 0;
  while (!done) {
    pfds[0].events = POLLIN;
    pfds[1].events = POLLIN;
    pfds[0].revents = 0;
    pfds[1].revents = 0;

    if (poll(pfds, 2, -1) == -1) {
      if (errno == EINTR) {
        continue;
      }
      break;
    }

    if (pfds[0].revents & POLLIN) {
      if (mdns_relay_once(client_fd, host_fd) <= 0) {
        done = 1;
      }
    }
    if (!done && (pfds[1].revents & POLLIN)) {
      if (mdns_relay_once(host_fd, client_fd) <= 0) {
        done = 1;
      }
    }
    // A hangup with no remaining data to drain ends the session.
    if (((pfds[0].revents | pfds[1].revents) & (POLLHUP | POLLERR)) &&
        !((pfds[0].revents | pfds[1].revents) & POLLIN)) {
      done = 1;
    }
  }

  close(host_fd);
  close(client_fd);
  return NULL;
}

static void *mdns_proxy_accept_thread(void *arg) {
  int listen_fd = (int)(intptr_t)arg;

  while (mdns_proxy_running) {
    int client = accept(listen_fd, NULL, NULL);
    if (client == -1) {
      if (errno == EINTR) {
        continue;
      }
      break; // listen socket closed during shutdown
    }

    pthread_t t;
    if (pthread_create(&t, NULL, mdns_conn_thread, (void *)(intptr_t)client) !=
        0) {
      close(client);
      continue;
    }
    pthread_detach(t);
  }

  return NULL;
}

int mdns_proxy_start(const char *container_root) {
  // Ensure the directory that holds the socket exists. These run before
  // sandbox_init(), so the writes are unrestricted.
  char dir[MAX_PATH_LEN];
  snprintf(dir, sizeof(dir), "%s/var", container_root);
  mkdir(dir, 0755);
  snprintf(dir, sizeof(dir), "%s/var/run", container_root);
  mkdir(dir, 0755);

  char path[MAX_PATH_LEN];
  mdns_proxy_socket_path(container_root, path, sizeof(path));

  struct sockaddr_un addr;
  if (strlen(path) >= sizeof(addr.sun_path)) {
    fprintf(stderr,
            "mdns proxy: socket path too long for AF_UNIX; DNS proxying "
            "disabled\n");
    return -1;
  }

  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd == -1) {
    perror("mdns proxy: socket");
    return -1;
  }

  unlink(path); // clear any stale socket from a previous run
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);
  if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
    perror("mdns proxy: bind");
    close(fd);
    return -1;
  }
  if (listen(fd, 16) == -1) {
    perror("mdns proxy: listen");
    close(fd);
    unlink(path);
    return -1;
  }

  // dns_sd clients launched inside the container will connect here instead of
  // the default /var/run/mDNSResponder. Set in our own environment so it is
  // inherited by the commands we spawn.
  setenv("DNSSD_UDS_PATH", path, 1);

  strncpy(mdns_proxy_path, path, sizeof(mdns_proxy_path) - 1);
  mdns_proxy_path[sizeof(mdns_proxy_path) - 1] = '\0';
  mdns_listen_fd = fd;
  mdns_proxy_running = 1;

  pthread_t t;
  if (pthread_create(&t, NULL, mdns_proxy_accept_thread,
                     (void *)(intptr_t)fd) != 0) {
    perror("mdns proxy: pthread_create");
    close(fd);
    unlink(path);
    mdns_proxy_running = 0;
    mdns_listen_fd = -1;
    return -1;
  }
  pthread_detach(t);

  printf("mDNSResponder proxy listening at %s\n", path);
  return 0;
}

void mdns_proxy_stop(void) {
  if (!mdns_proxy_running) {
    return;
  }
  mdns_proxy_running = 0;
  if (mdns_listen_fd != -1) {
    close(mdns_listen_fd); // unblocks accept() in the proxy thread
    mdns_listen_fd = -1;
  }
  if (mdns_proxy_path[0] != '\0') {
    unlink(mdns_proxy_path);
    mdns_proxy_path[0] = '\0';
  }
}
