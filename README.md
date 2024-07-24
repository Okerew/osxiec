# Osxiec

OSXIEC is a native docker-like solution for macOS developed by Okerew. It leverages native macOS features to provide containerization capabilities, albeit with some limitations compared to Docker.

<a href="https://youtu.be/CkJT0STyIZE" target="_blank">
 <img src="https://github.com/user-attachments/assets/d45e77d8-9532-482f-b4f6-874a301f4916" alt="Watch the video" />
</a>
If it says that macOS can't identify if it is malware or not, close it go into settings and allow it to be executed.

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

**Containerize a Directory**: containerizes a directory
```sh
sudo osxiec -contain {directory_path} {some_name}.bin {path_to_config_file_in_directory_path}
```

**Execute a Container**: executes container
```sh
sudo osxiec -execute {some_name}.bin 
```

**Execute with Port Argument**: execute with port
```sh
sudo osxiec -execute {some_name} -port {PORT_NUMBER}
```
**Create a cluster ( virtualized network )** create a cluster
```sh
sudo osxiec -network create {network_name} {vlan_id}
```
**Run with vlan config** run with vlan config
``` sh
sudo osxiec -run {some_name} {network_name} -port {PORT_NUMBER}
```
**Version** checks the current version
```sh
osxiec --version
```
**Pull** pulls an image from osxiec hub
```sh
osxiec -pull {container_name}
```
**Search** searches osxiec hub
```sh
osxiec -search {search_term_for_osxiec_hub}
```
**Upload** allows to upload a file to osxiec hub
```sh
osxiec -upload {filename} {username} {password} {description}
```
**Convert to Docker** converts to docker
```sh
osxiec -convert-to-docker {bin_file} {output_directory} {base_image} [custom_dockerfile]
```
**Clean** this will clean the container volume images from /tmp 
```sh
sudo osxiec -clean
```

**Help** shows all the commands
```sh
osxiec -help
```

## Creating a container
To create a container firstly make sure that the directory you want to contain is structured like this.
``` 
[
    "container_name",
    {
        "contents",
        "start_config_file"
        
        "layers": [
            "Here will be the layers, for example:"
             {
                 "layer1": "here will be the 1 layer dir"
             }
             {
                 "layer2": "here will be the 2 layer dir"
             }
        ]
    }    
    
]
```
Then run the `osxiec -contain {directory_path} {container_name} {start_config_file}`

## Executing a container
After creating a container or downloading one.
**You can execute one with**

`osxiec -execute {container_name}` 

If you want you can also use a custom port with `-port {PORT_NUMBER}`

**Run with vlan**

If you have created a vlan network like said in the next point you can run the container with 

```osxiec -run {container_name} {network_name}``` 

You can also add the port argument with `-port {PORT_NUMBER}`

**When executing**
<br>
Normally it will start a listener which will allow it to communicate with other containers. 
![Screenshot 2024-07-24 at 18 11 30](https://github.com/user-attachments/assets/50d308ce-60bc-4355-a60d-a05430cea2df)

If you want to access the container terminal just press enter.
![Screenshot 2024-07-24 at 18 11 45](https://github.com/user-attachments/assets/32762bb2-0eb0-492e-9d04-1fcf1b8b80f8)

## Creating a vlan network
To create a network you can run `osxiec -network create {network_name} {vlan_id}`

The network_name can be any string like "test" for example.

The vlan id can be any number from 1-4094.

For example `osxiec -network create test 6` 
## Converting to Docker
**Create docker file** 
``` dockerfile
# Test Dockerfile for osxiec to Docker conversion

# Use a lightweight base image
FROM alpine:latest

# Set the working directory in the container
WORKDIR /app

# Copy the application files from the osxiec container
# Note: This will be handled by the conversion script, so we don't need COPY instructions here

# Install any needed packages
RUN apk add --no-cache python3 py3-pip

# Set environment variables (these will be overwritten by the conversion script if not using a custom Dockerfile)
ENV MEMORY_SOFT_LIMIT=256m
ENV MEMORY_HARD_LIMIT=512m
ENV CPU_PRIORITY=20

# Make port 8080 available to the world outside this container
EXPOSE 8080

# Run a simple Python HTTP server when the container launches
CMD ["python3", "-m", "http.server", "8080"]
```
**Run convert-to-docker**

For this example
```sh
osxiec -convert-to-docker {container_name} {output_directory} alpine:latest samples/dockerfile
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
![Screenshot 2024-07-24 at 18 25 20](https://github.com/user-attachments/assets/451f7851-ac64-4d59-9654-6729906fd01d)

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
- **Sandbox deprecation error** yes I know that sandbox innit is deprecated but there isn't really an alternative for it unless I would use xcode and there is no way I am using it to rebuild this.
---
