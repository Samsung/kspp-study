#!/bin/bash

ROOT=/bench
KERN=linux-4.19.56
LINK=https://cdn.kernel.org/pub/linux/kernel/v4.x/$KERN.tar.xz
RUNS=5

if [[ $(id -u) != 0 ]]; then
   echo "[!] run $0 w/ root"
   exit 1
fi

mkdir -p $ROOT
cd $ROOT

if [[ ! -e $KERN ]]; then
   wget $LINK
   tar xf $KERN.tar.xz
fi

cd $KERN

perf stat --repeat 5 --null --pre                    '\
     make defconfig                                   \
     make clean >/dev/null 2>&1;                      \
     echo 1 > /proc/sys/vm/drop_caches;               \
     sync                                            '\
     make -j$(ncpus) >/dev/null
