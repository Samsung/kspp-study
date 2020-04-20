#!/bin/bash

ROOT=$(realpath $(dirname "$0"))
RELEASE=https://github.com/rust-lang-nursery/mdBook/releases/download/v0.3.1/mdbook-v0.3.1-x86_64-unknown-linux-gnu.tar.gz
MDBOOK=$ROOT/mdbook

if [[ ! -e $MDBOOK ]]; then
    pushd $ROOT
    wget $RELEASE -O mdbook.tar.gz
    tar xvf mdbook.tar.gz
    rm mdbook.tar.gz
    popd
fi

$MDBOOK "$@"
