#!/usr/bin/env python3

import os
import sys

if len(sys.argv) != 2:
    print("[!] %s [script]" % sys.argv[0])
    exit(1)

init = os.path.abspath(sys.argv[1])

if os.getuid() != 0:
    print("[!] please run w/ root")
    exit(2)

CFG = "/boot/grub/grub.cfg"
os.system(f"cp {CFG} {CFG}.old")

cfg = []
for l in open(CFG):
    if "/boot/vmlinuz-5.0.0 root" in l:
        l = l.rstrip() + " init=%s\n" % init
    cfg.append(l)

with open(CFG, "w") as fd:
    fd.write("".join(cfg))

os.system("grub-reboot 0")
os.system("sync")
os.system("reboot")
