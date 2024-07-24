# Osxiec

OSXIEC is a native docker-like solution for macOS developed by Okerew. It leverages native macOS features to provide containerization capabilities, albeit with some limitations compared to Docker.

<a href="https://youtu.be/CkJT0STyIZE" target="_blank">
 <img src="https://github.com/user-attachments/assets/d45e77d8-9532-482f-b4f6-874a301f4916" alt="Watch the video" />
</a>
If it says that macOS can't indentify if it is malware or not, close it go into settings and allow it to be executed.

____


## Dependencies
**HomeBrew for installing dependencies**
```sh
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```
**Curl**
```sh
brew install curl
```
**Readline**
```sh
brew install readline
```
**Ninja for building**
```sh
brew install ninja
```
**Cmake for building**
``` sh
brew install cmake
```
## Installation

1. **Download the Release**:
   Download the `osxiec.tar.gz` or `osxiec_gui.tar.gz` file from the releases section.

2. **Extract the Archive**:
   ```sh
   tar -xvzf osxiec.tar.gz
   ```

3. **Copy the Executable to PATH**:
   ```sh
   sudo cp osxiec /usr/local/bin/
   ```
 4. **If downloaded osxiec_gui**
   ```
   Copy app bundle to /Applications then run the app bundle or run osxiec.jar 
   ```

To update to a new release, remove the old executable and follow the installation steps again:
```sh
sudo rm /usr/local/bin/osxiec
```
Then repeat steps 1, 2, and 3 if using osxiec_gui also step 4.

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
**Convert to Docker**
```sh
osxiec -convert-to-docker {bin_file} {output_directory} {base_image} [custom_dockerfile]
```
**Clean**
```sh
sudo osxiec -clean
```
**Help**
```sh
osxiec -help
```

## Debugging

When in a container, you can use the following commands to debug the container.
<br>
To start debugging `debug`
<br>
Then you can use these commands
___
``` 
step
```
which steps to the next command
___
``` 
break <command>
```
Creates a breakpoint at the specified command
___
``` 
print <var>
```
Prints the value of the specified variable of the container
___
``` 
print
```
Prints the whole container state
___
``` 
help
```
Shows what you can do
___
``` 
continue
```
Continues execution of the container
_____
### <a href="https://osxiec.glitch.me">Osxiec Container Hub</a>
This is a place where you can upload your containers to.
___
### <a href="https://github.com/Okerew/osxiec_gui">Osxiec Gui</a>
This is the source code for the gui version of osxiec.
![Screenshot 2024-07-24 at 12 05 58](https://github.com/user-attachments/assets/42d858e1-e4fd-4a82-b2e8-f86a7c35be38)

___
## Building
**Git clone the repository**
``` sh
git clone https://github.com/Okerew/osxiec.git
```
**Go to the directory**
``` sh
cd osxiec
```
**Build the executable**
``` sh
mkdir {build-directory}
cd {build-directory}
cmake -S .. -B . -G "Ninja"
ninja
```

## Plugins
**Example plugin** can be seen in samples/sample_plugin.c, this should make you understand how osxiec loads plugins.

**Build plugin**
``` sh
gcc -shared -fPIC -o {plugin_name}.so {plugin_name}.c  
```

**Install plugin**

``` sh 
sudo cp {plugin_name}.so  ~/.osxiec/plugins
```
After this on the execution of osxiec command the plugin will be loaded.
## Notes

- **Not a Docker Replacement**:
  While OSXIEC offers similar functionality to Docker, it lacks some advanced features of Docker. It is more supposed to be a quicker testing tool than docker on macOS, it is not designed to replace it, just to test basic ideas and software.

- **macOS Only**:
  OSXIEC uses native macOS features and is not compatible with other operating systems.

- **Isolation Limitations**:
  Due to macOS limitations, complete isolation like in Linux is not possible. The contained directory will have some access to the outside environment, hence no config file is needed.

- **Supported Features**:
  Despite its limitations, OSXIEC provides isolation using namespaces, setuid, image layers, basic user process control, memory and CPU control, and special permissions using user IDs and group IDs, unpacking the image into a disk image(APFS), vlans.

- **Layer Configuration**:
  Ensure a layers folder exists with specified layers as shown in the example folder.
- **Support**: Remember that not everything will work for example node won't work because it is making sys calls which spawn things outside the container.
- **Temps**: If you need a lot of storage for the moment, and you used a container use the clean command. 

- **Why is chroot not used?**
  Chroot requires for SIP to be disabled, which causes many security risks, chroot can be easily exited by any process, using the normal macOS restrictions is way more secure, and reliable
  it causes many permission issues, apple does not really like it and will probably make it harder to use it later on in the future.
---
