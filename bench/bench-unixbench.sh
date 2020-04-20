#!/bin/bash

ROOT=$(realpath $(dirname "$0"))
LOG=$ROOT/log
UNIXBENCH=unixbench
ID=$(date +%Y-%m-%d-%s)

cd $ROOT

sudo apt install libx11-dev libgl1-mesa-dev libxext-dev perl perl-modules make git

if [[ ! -e $UNIXBENCH.zip ]]; then
    wget https://codeload.github.com/kdlucas/byte-unixbench/zip/master -O $UNIXBENCH.zip
fi

if [[ ! -e $UNIXBENCH ]]; then
    unzip $UNIXBENCH.zip
    mv byte-unixbench-master $UNIXBENCH
fi

cd $UNIXBENCH/UnixBench
./Run

mkdir -p $LOG
mv results $LOG/$UNIXBENCH-$ID
