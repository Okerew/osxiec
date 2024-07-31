#!/bin/bash

# Check if the script is run as root
if [ "$EUID" -ne 0 ]
  then echo "Please run as root or use sudo"
  exit
fi

files_to_copy=("osxiec" "osxiec_deploy_multiple.sh")

# Delete existing files and copy the new ones to /usr/local/bin
for file in "${files_to_copy[@]}"
do
  if [ -f "/usr/local/bin/$file" ]; then
    rm "/usr/local/bin/$file"
    echo "Deleted existing file /usr/local/bin/$file"
  fi

  cp "$file" /usr/local/bin/

  # Check if the copy was successful
  if [ $? -eq 0 ]; then
    echo "File $file copied successfully to /usr/local/bin"
  else
    echo "Failed to copy the file $file"
  fi
done

echo "Installation complete!"
