#!/bin/sh

ROOT=$(realpath $(dirname "$0"))
KERN=$ROOT/linux-5.0/vmlinux
LOG=$ROOT/structleak-$(date +%Y-%m-%d-%s).log

check() {
    $ROOT/build.sh +$1 +GCC_PLUGIN_STRUCTLEAK +GCC_PLUGINS
    echo $1 >> $LOG
    size $KERN >> $LOG
}

check INIT_STACK_NONE
check GCC_PLUGIN_STRUCTLEAK_USER
check GCC_PLUGIN_STRUCTLEAK_BYREF
check GCC_PLUGIN_STRUCTLEAK_BYREF_ALL
check INIT_STACK_ALL
