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
### Build Dependencies
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
   Download the `osxiec_cli.tar.gz` and `osxiec_gui.tar.gz` if you want a gui app file from the releases section.

2. **Extract the Archive**:
   ```sh
   tar -xvzf osxiec_cli.tar.gz
   ```
   For gui version
   ```sh
   tar -xvzf osxiec_gui.tar.gz
   ```

3. **Run installation script in the extracted cli directory**:
   ```sh
   sudo sh install.sh 
   ```
4. **If downloaded osxiec_gui**
   ```
   Copy app bundle from osxiec_gui.tar.gz to /Applications then run the app bundle or run osxiec.jar 
   ```

To update to a new release, repeat steps 1, 2, and 3 if using osxiec_gui also step 4.
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
**Remove a vlan network** removes a vlan network
```sh
sudo osxiec -network remove {network_name} {vlan_id}
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

**Detach** detaches the container images
```sh
osxiec -detach
```

**Help** shows all the commands
```sh
osxiec -help
```

**Deploy** deploys a container
```sh
sudo osxiec -deploy {path_to_config} -port {PORT_NUMBER}
```

**Scan** scans a container for security vulnerabilities
```sh
osxiec -scan {some_name.bin}
```

**Deploym** deploys multiple containers, this is a work in progress, for now it works mostly fine with start config
```sh
sudo osxiec -deploym {config_file}
```

**Oexec** executes a container in offline mode without any networking or usage of ports
```sh
sudo osxiec -oexec {bin_file_path}
```

**Extract** extracts files and folders from a container
```sh
sudo osxiec -extract {bin_file_path}
```

## Creating a container
Make sure to include any dependencies or executables you can obtain these by searching for where a dependency or executable is located and copying it along with it's dependencies.


**Example structure**
``` 
[
    "container_name",
    {
        "some_content",
        "subfolder1" [
           executable1
           "some_content"
         ]
        "start_config_file"
        "some_executable"
        "dependency"
    }    
    
]
```
<br>

**Script Example:**
For example if you have a node project make sure to include somewhere the node executable in the directory you want to contain, then run the script with the node executable.

``` js
console.log("Hello World")
```

Do `path/to/node_executable_in_container/ script.js`

<br>

**Containing**

To contain a directory run the `osxiec -contain {directory_path} {container_name} {start_config_file}`

This will also scan the container for security vulnerabilities.
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


## Container commands
1. **help** shows all the commands
2. **debug** debugs the container
3. **scale** scales the resources of the container
4. **osxs** Execute an osxs script file
5. **xs** Execute an osxs script command
6. **autoscale** automatically scales the resources of the container
7. **status** shows the status of the container
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

## Deploying
**Create a config file**
```
source_dir=/path/to/source/directory
container_file=/path/to/output/container.bin
network_name=my_network
start_config=/path/to/start_config.sh
```
**Deploy**
```sh
sudo osxiec -deploy {path_to_config_file} 
``` 
You can also use `-port {PORT_NUMBER}`

**Deploym**
you can also deploy multiple containers, this is a work in progress though.
```sh
sudo osxiec -deploym {config_file} {PORT_NUMBER1} {PORT_NUMBER2} etc.
``` 
**Config**

```
path_to_container1_config {network_name}
path_to_container2_config {network_name}
```

## Osxiec Script
Osxiec script is a scripting language created for managing osxiec containers.
### Syntax
**Set Memory**
```sh
SET_MEMORY {memory_soft} {memory_hard}
```
**Set CPU Priority**
```sh
SET_CPU {cpu_priority}
```
**Execute**
```sh
EXECUTE {command}
```
**Conditional Execution**
```sh
IF {condition} EXECUTE {command}
```
**Sleep**
```sh
SLEEP {seconds}
```
**Log**
```sh
LOG {message}
```
**Execute File**
```sh
EXECUTE_FILE {path_to_script}
```
**Set Variable**
```sh
SET {variable} {value}
```
**While Loop**
```sh
WHILE {condition} {commands} END
```
**For Loop**
```sh
FOR {variable} TO {2variable} STEP {value} {commands} END
```

**ELSE**
```sh
IF {condition} ELSE {commands} END
```
Note ELSE statement for now doesn't work with LOG and is a work in progress

**Example**
```
# This is an example script for the OSXIEC scripting language
SET counter 0
SET limit 10

# Loop from 0 to 10
FOR counter=0 TO limit STEP 2
    IF counter==5
        LOG "Counter is 5"
    END
    SLEEP 1
END

IF $var==5 LOG Variable is 5 ELSE LOG Variable is not 5

# Loop while counter is less than limit
WHILE counter<limit
    IF counter==5
        LOG "Counter is 5"
    END
    SET counter $(($counter + 1))
    SLEEP 1
END

# Log the start of the script
LOG Starting script for $container_name

# Set container memory limits
SET_MEMORY $mem_soft $mem_hard

# Set CPU priority
SET_CPU $cpu_priority

# Execute a command
EXECUTE echo "Container $container_name initialized"

# Conditional execution
SET status running
IF status==running EXECUTE echo "Container is operational"

# Sleep for 2 seconds
SLEEP 2

# Echo some information
ECHO Container $container_name is configured with:
ECHO - Memory limits: $mem_soft MB (soft) / $mem_hard MB (hard)
ECHO - CPU priority: $cpu_priority
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
### <a href="https://github.com/Okerew/osxiec_terminal.git">Osxiec Terminal</a>
A terminal emulator specifically created for osxiec
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
**Build the osxiec executable**
``` sh
mkdir {build-directory}
cd {build-directory}
cmake -S .. -B . -G "Ninja"
ninja
```

**Build terminal**
golang is required for this one
``` sh
cd term
go build term.go
```

**Give permissions to scripts if needed**
``` sh
sudo chmod +x scripts/osxiec_deploy_multiple.sh
sudo chmod +x scripts/install.sh
```
**Finalize**
to make it work put all executables in a one folder, copy there install.sh and run it

### Build java gui
Git clone the gui
```sh
git clone https://github.com/Okerew/osxiec_gui.git
```

Go to the directory
```sh
cd osxiec_gui
```
Build the class
```sh
javac OsxiecApp.java
```
Build the jar
```sh
jar -cvfe osxiec.jar OsxiecApp OsxiecApp.class
```

Copy jar into app bundle, remove the previous one
```sh
cp osxiec.jar osxiec.app/Contents/Resources
```
If using the one from release, delete the previous one

Copy the icon into Contents/Resources

Finally, copy the run_app_bundle.sh into the bundle as osxiec_gui
```sh
cp run_app_bundle.sh osxiec.app/Contents/MacOS/osxiec_gui
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
  While OSXIEC offers similar functionality to Docker, it lacks some advanced features of Docker. It is more supposed to be a quicker testing tool than docker on macOS, it is not designed to replace it, just to test basic ideas and software, distribute macOS software.
- **macOS Only**:
  OSXIEC uses native macOS features and is not compatible with other operating systems.
- **Isolation Limitations**:
  Due to macOS limitations, complete isolation like in Linux is not possible. The contained directory will have some access to the outside environment, you can have a start config file if needed.
- **Supported Features**:
  Despite its limitations, OSXIEC provides isolation using namespaces, setuid, image layers, basic user process control, memory and CPU control, and special permissions using user IDs and group IDs, unpacking the image into a disk image(APFS), vlans.
- **Support**: Remember that not everything will work fully for example node won't work fully because it is making sys calls which spawn things outside the container, in this example local things that do not rely on the repl server will work.
- **Temps**: If you need a lot of storage for the moment, and you used a container use the clean command.
- **Why is chroot not used?**
  Chroot requires for SIP to be disabled, which causes many security risks, chroot can be easily exited by any process, using the normal macOS restrictions is way more secure, reliable,
  having it disabled causes many permission issues.
- **Sandbox deprecation error** yes I know that sandbox innit is deprecated but there isn't really an alternative for it unless I would use xcode and there is no way I am using it to rebuild this.
---

## License
For detailed information on your rights and obligations, please refer to the two license files provided. Each file outlines what you are permitted to do under the respective license terms.
