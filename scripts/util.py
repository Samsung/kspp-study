#!/usr/bin/env python3

import os
import re
import subprocess
import sys
import pickle

from collections import defaultdict


def disasm(pn):
    return subprocess.check_output(["objdump", "-Mintel",
                                    "--no-show-raw-insn", "-d", pn],
                                   universal_newlines=True).splitlines()

def get_funcs(asm):
    funcs = []
    for l in asm:
        m = re.match(r"[\d\w]+ <([^>]+)>:", l)
        if m:
            funcs.append(m[1])
    return funcs

def count_func(asm):
    return len(get_funcs(asm))

def count_canary(asm):
    ncanary = 0
    for l in asm:
        if "call" in l and "<__stack_chk_fail>" in l:
            ncanary += 1
    return ncanary

def has_canary(asm):
    for l in asm:
        if "call" in l and "<__stack_chk_fail>" in l:
            return True
    return False

def _load_cache(pn):
    cache = os.path.join("/tmp", ".xxx-" + os.path.basename(pn))
    if os.path.exists(cache) \
       and os.stat(cache).st_mtime > os.stat(pn).st_mtime:
        print("[!] loading: %s" % cache)
        with open(cache, "rb") as fd:
            return pickle.load(fd)
    return None

def _save_cache(pn, funcs):
    cache = os.path.join("/tmp", ".xxx-" + os.path.basename(pn))
    print("[!] saving: %s" % cache)
    with open(cache, "wb") as fd:
        pickle.dump(funcs, fd)

# a few caveats:
#  1) multiple func names (for static): e.g., find_patch
#  2) thunk-like
def load_funcs(pn):
    funcs = _load_cache(pn)
    if funcs:
        return funcs

    # parse
    funcs = defaultdict(list)
    asm = disasm(pn)

    func = None
    for l in asm:
        l = l.strip()
        if len(l) == 0:
            continue
        if "Disassembly of section" in l:
            continue

        m = re.match(r"([\d\w])+ <([^>]+)>:", l)
        if m:
            func = m[2]
            continue
        
        if func:
            funcs[func].append(l)

    _save_cache(pn, funcs)

    return funcs

def get_func_size(func):
    if len(func) == 0:
        return 0
    
    def _get_addr(asm):
        return int(asm.split()[0].rstrip(":"), 16)

    return _get_addr(func[-1]) - _get_addr(func[0])

def normalize(asm):
    norm = ["size = %d" % get_func_size(asm)]
    beg = None

    for l in asm:
        # drop address
        addr = int(l[:l.index(":")], 16)
        if beg is None:
            beg = addr

        l = "%08x: %s" % (addr - beg, l[l.index(":")+1:].strip())
        # drop addr
        if l.startswith("j") or l.startswith("call"):
            l = re.sub(r"ffffffff[\d\w]+", "????????", l)
        norm.append(l)
    return norm

def normalize2(asm):
    norm = ["size = %d" % get_func_size(asm)]

    for l in asm:
        # drop address
        l = l[l.index(":")+1:].strip()
        # drop addr
        if l.startswith("j") or l.startswith("call"):
            l = re.sub(r"ffffffff[\da-f]+", "????????", l)
        elif l.startswith("mov") or l.startswith("cmp"):
            if "#" in l:
                l = l.rsplit("#")[0].strip()
                
        # drop constants
        l = re.sub(r"0x[\da-f]+", "????", l)
        norm.append(l)
    return norm
