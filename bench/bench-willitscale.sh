#!/bin/bash

ROOT=$(realpath $(dirname "$0"))
LOG=$ROOT/log
BENCH=willitscale
ID=$(date +%Y-%m-%d-%s)

cd $ROOT

sudo apt install libhwloc-dev

if [[ ! -e $BENCH.zip ]]; then
    wget https://codeload.github.com/antonblanchard/will-it-scale/zip/master -O $BENCH.zip
fi

if [[ ! -e $BENCH ]]; then
    unzip $BENCH.zip
    mv will-it-scale-master $BENCH
fi

cd $BENCH
make

./runalltests
python2 ./postprocess.py

DIR=$LOG/$BENCH-$ID
mkdir -p $DIR
mv *.html $DIR/
