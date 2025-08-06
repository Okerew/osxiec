#!/bin/bash

# Define the version of the installation
OSXIEC_VERSION="1.0"

# Check if the script is run as root
if [ "$EUID" -ne 0 ]
  then echo "Please run as root or use sudo"
  exit
fi

# Define the files and directories to copy
files_to_copy=("osxiec" "libosxiec.dylib" "osxiec_deploy_multiple.sh" "include" "README.md" "LICENSE")

# Define the destination directory
install_dir="/usr/local/Cellar/osxiec/$OSXIEC_VERSION"

# Create the installation directories
mkdir -p "$install_dir/lib" "$install_dir/include" "$install_dir/bin"

# Copy each file or directory
for item in "${files_to_copy[@]}"
do
  # Check if it's a directory or file
  if [ -d "$item" ]; then
    if [ "$item" == "include" ]; then
      if [ -d "$install_dir/include/osxiec" ]; then
        rm -rf "$install_dir/include/osxiec"
        echo "Deleted existing directory $install_dir/include/osxiec"
      fi
      cp -r "$item" "$install_dir/include/osxiec/"
      
      # Check if the copy was successful
      if [ $? -eq 0 ]; then
        echo "Directory $item copied successfully to $install_dir/include/osxiec"
      else
        echo "Failed to copy the directory $item"
      fi
    else
      # For any other directory, copy it directly to the version folder
      cp -r "$item" "$install_dir/"
      
      # Check if the copy was successful
      if [ $? -eq 0 ]; then
        echo "Directory $item copied successfully to $install_dir"
      else
        echo "Failed to copy the directory $item"
      fi
    fi
  elif [ -f "$item" ]; then
    if [ "$item" == "osxiec" ]; then
      # Check and delete existing symbolic link if present
      if [ -L "/usr/local/bin/osxiec" ]; then
        rm "/usr/local/bin/osxiec"
        echo "Deleted existing symbolic link /usr/local/bin/osxiec"
      fi

      # Copy the executable to the bin folder in the versioned directory
      if [ -f "$install_dir/bin/$item" ]; then
        rm "$install_dir/bin/$item"
        echo "Deleted existing file $install_dir/bin/$item"
      fi
      cp "$item" "$install_dir/bin/"
      
      # Check if the copy was successful
      if [ $? -eq 0 ]; then
        echo "Executable $item copied successfully to $install_dir/bin"
      else
        echo "Failed to copy the executable $item"
      fi

      # Create a new symbolic link in /usr/local/bin pointing to the executable in the bin folder
      ln -s "$install_dir/bin/osxiec" "/usr/local/bin/osxiec"
      if [ $? -eq 0 ]; then
        echo "Symbolic link created in /usr/local/bin pointing to $install_dir/bin/osxiec"
      else
        echo "Failed to create symbolic link in /usr/local/bin"
      fi
    elif [ "$item" == "libosxiec.dylib" ]; then
      # Check and delete existing symbolic link if present
      if [ -L "/usr/local/lib/libosxiec.dylib" ]; then
        rm "/usr/local/lib/libosxiec.dylib"
        echo "Deleted existing symbolic link /usr/local/lib/libosxiec.dylib"
      fi

      # For libosxiec.dylib, copy to the lib folder in the versioned directory
      if [ -f "$install_dir/lib/$item" ]; then
        rm "$install_dir/lib/$item"
        echo "Deleted existing file $install_dir/lib/$item"
      fi
      cp "$item" "$install_dir/lib/"
      
      # Check if the copy was successful
      if [ $? -eq 0 ]; then
        echo "File $item copied successfully to $install_dir/lib"
      else
        echo "Failed to copy the file $item"
      fi

      # Create a new symbolic link in /usr/local/lib to the library
      ln -s "$install_dir/lib/libosxiec.dylib" "/usr/local/lib/libosxiec.dylib"
      if [ $? -eq 0 ]; then
        echo "Symbolic link created in /usr/local/lib pointing to $install_dir/lib/libosxiec.dylib"
      else
        echo "Failed to create symbolic link in /usr/local/lib"
      fi
    elif [ "$item" == "osxiec_deploy_multiple.sh" ]; then
      if [ -f "/usr/local/bin/$item" ]; then
        rm "/usr/local/bin/$item"
        echo "Deleted existing file /usr/local/bin/$item"
      fi

      cp "$item" /usr/local/bin/
      if [ $? -eq 0 ]; then
        echo "File $item copied successfully to /usr/local/bin"
      else
        echo "Failed to copy the file $item"
      fi
    else
      # For any other file, copy it directly into the version folder
      cp "$item" "$install_dir/"
      
      # Check if the copy was successful
      if [ $? -eq 0 ]; then
        echo "File $item copied successfully to $install_dir"
      else
        echo "Failed to copy the file $item"
      fi
    fi
  else
    echo "$item does not exist or is not a valid file or directory"
  fi
done

echo "Installation complete!"
