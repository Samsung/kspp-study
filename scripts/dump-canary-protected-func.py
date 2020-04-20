#!/usr/bin/env python3

from util import *

if len(sys.argv) != 2:
    print("[!] %s vmlinux" % sys.argv[0])
    exit(1)

funcs = load_funcs(sys.argv[1])
for f in funcs:
    if has_canary(funcs[f]):
        print(f, get_func_size(funcs[f]))
