# OSXIEC: A Native Docker-like Solution for macOS by Okerew

![osxiec_icon](https://github.com/user-attachments/assets/d45e77d8-9532-482f-b4f6-874a301f4916)

## Introduction

OSXIEC is a native Docker-like solution for macOS developed by Okerew. It leverages native macOS features to provide containerization capabilities, albeit with some limitations compared to Docker. <a href="https://osxiec.glitch.me">Osxiec Hub</a>

## Installation

1. **Download the Release**:
   Download the `osxiec.tar.gz` file from the releases section.

2. **Extract the Archive**:
   ```sh
   tar -xvzf osxiec.tar.gz
   ```

3. **Copy the Executable to PATH**:
   ```sh
   sudo cp osxiec /usr/local/bin/
   ```

To update to a new release, remove the old executable and follow the installation steps again:
```sh
sudo rm /usr/local/bin/osxiec
```
Then repeat steps 1, 2, and 3.


## Usage

**Containerize a Directory**:
```sh
sudo osxiec -contain {directory_path} {some_name}.bin {path_to_config_file_in_directory_path}
```

**Execute a Container**:
```sh
sudo osxiec -execute {some_name}.bin
```

**Execute with Port Argument**:
```sh
sudo osxiec -execute {some_name} -port {PORT_NUMBER}
```
**Create a cluster ( virtualized network )**
```sh
sudo osxiec -network create {network_name} {vlan_id}
```
**Run with vlan config**
``` sh
sudo osxiec -run {some_name} {network_name} -port {PORT_NUMBER}
```
**Version**
```sh
osxiec --version
```
**Pull**
```sh
osxiec -pull {container_name}
```
**Search**
```sh
osxiec -search {search_term_for_osxiec_hub}
```
**Upload**
```sh
osxiec -upload {filename} {username} {password} {description}
```
**Help**
```sh
osxiec -help
```
## Building
**Git clone the repository**
``` sh
git clone https://github.com/Okerew/osxiec
```
**Build the executable**
```sh
gcc -o osxiec osxiec.c -lcurl
```
## Notes

- **Not a Docker Replacement**:
  While OSXIEC offers similar functionality to Docker, it lacks some advanced features of Docker.

- **macOS Only**:
  OSXIEC uses native macOS features and is not compatible with other operating systems.

- **Isolation Limitations**:
  Due to macOS limitations, complete isolation like in Linux is not possible. The contained directory will have some access to the outside environment, hence no config file is needed.

- **Supported Features**:
  Despite its limitations, OSXIEC provides isolation using namespaces, setuid, image layers, basic user process control, memory and CPU control, and special permissions using user IDs and group IDs, unpacking the image into a disk image(APFS), vlans.

- **Layer Configuration**:
  Ensure a layers folder exists with specified layers as shown in the example folder.
- **Support**: Remember that not everything will work for example node won't work because it is making sys calls which spawn things outside the container.
- **Temps**: If you need a lot of storage for the moment, and you used a container, delete the dmg in /tmp folder, note these images are also deleted each time the system restarts.

- **Why is chroot not used?**
  Chroot requires for SIP to be disabled, which causes many security risks, chroot can be easily exited by any process, using the normal macOS restrictions is way more secure, and reliable
  it causes many permission issues, apple does not really like it and will probably make it harder to use it later on in the future.
---
