#!/usr/bin/env python3

from util import *

if len(sys.argv) != 3:
    print("[!] %s vmlinux func" % sys.argv[0])
    exit(1)

(vm, func) = sys.argv[1:]

funcs = load_funcs(vm)
print("name = %s, size = %d" % (func, get_func_size(funcs[func])))
print("\n".join(normalize(funcs[func])))
        
    
