#!/bin/bash

ROOT=$(pwd `dirname "$0"`)
KERN=linux-5.0
LINK=https://cdn.kernel.org/pub/linux/kernel/v5.x/$KERN.tar.xz
CONF=ubuntu-v5.0-rc8.config
BOOT=linux-5.0.0

if [[ $(id -u) == 0 ]]; then
   echo "[!] don't run $0 w/ root"
   exit 1
fi

if ! which ncpus &> /dev/null; then
  sudo apt -y install mdm
fi

cd $ROOT
if [[ ! -e $KERN.tar.xz ]]; then
   wget $LINK
fi
if [[ ! -e $KERN ]]; then
    tar xf $KERN.tar.xz
fi

cp $CONF $KERN/.config

cd $KERN

# e.g., +DEBUG_LIST -SLAB_FREELIST_HARDENED
ARGS=()
for c in "${@}"; do
    if [[ $c =~ ^\+.*$ ]]; then
	ARGS+=("-e")
    elif [[ $c =~ ^-.*$ ]]; then
	ARGS+=("-d")
    fi
    ARGS+=("${c:1}")
done

if [[ ${#ARGS[@]} != 0 ]]; then
  ./scripts/config "${ARGS[@]}"
  echo "${ARGS[@]}"
fi

ID=$(date +%Y-%m-%d-%s)

# default to all
make clean 2>&1 >/dev/null
yes "" | make oldconfig
make -j$(ncpus) > build-$ID.log
make modules >> build-$ID.log

# cleanup /boot entry
sudo rm -f /boot/config-5.0.0
sudo rm -f /boot/initrd.img-5.0.0
sudo rm -f /boot/System.map-5.0.0
sudo rm -f /boot/vmlinuz-5.0.0

sudo make modules_install install
