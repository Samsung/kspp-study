#!/usr/bin/env python3

from util import *

if len(sys.argv) != 3:
    print("[!] %s vmlinux1 vmlinux2" % sys.argv[0])
    exit(1)

(vm1, vm2) = sys.argv[1:]

funcs1 = load_funcs(vm1)
funcs2 = load_funcs(vm2)

for f in funcs1:
    s1 = get_func_size(funcs1[f])
    s2 = get_func_size(funcs2[f])
    if s1 != s2:
        print("%-40s: %10d vs %10d (diff = %d)" % (f, s1, s2, s2-s1))
        
    


