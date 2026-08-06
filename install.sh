#!/bin/bash

OSXIEC_VERSION="1.1.1"

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root or use sudo"
  exit
fi

cmake -B build && make -C build

install_dir="/usr/local/Cellar/osxiec/$OSXIEC_VERSION"

cmake --install build --prefix "$install_dir" --strip

cp README.md LICENSE "$install_dir/"
cp osxiec_deploy_multiple.sh /usr/local/bin/

if [ -L "/usr/local/bin/osxiec" ]; then
  rm "/usr/local/bin/osxiec"
fi
ln -s "$install_dir/bin/osxiec" "/usr/local/bin/osxiec"

if [ -L "/usr/local/lib/libosxiec.dylib" ]; then
  rm "/usr/local/lib/libosxiec.dylib"
fi
ln -s "$install_dir/lib/libosxiec.dylib" "/usr/local/lib/libosxiec.dylib"

echo "Installation complete!"
