#!/usr/bin/env python3

from util import *

assert len(sys.argv) > 1

for pn in sys.argv[1:]:
    print("[!] checking: %s (%d KB)" % (pn, os.path.getsize(pn)/1024))
    asm = disasm(pn)
    nfunc = count_func(asm)
    ncanary = count_canary(asm)

    print("=> %d/%d = %.2f%% have a canary check" \
          % (ncanary, nfunc, ncanary/nfunc*100.0))
