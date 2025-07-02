# CVE-2020-6465 – Chrome Sandbox Bypass via Mojo and LFH Exploit Chain

## Overview

This exploit chain demonstrates CVE-2020-6465—a vulnerability that enables a sandbox bypass in vulnerable versions of Chrome. The exploit leverages multiple advanced techniques:
 
- **LFH-Style Memory Manipulation:** Using iframes to force allocations in a Low Fragmentation Heap (LFH) environment.
- **Mojo Interface Interception:** Employing Chrome’s Mojo IPC framework to leak pointers from freed memory.
- **Custom Heap Spraying:** Creating controlled allocations with the BlobRegistry and custom data pipes to prepare a precise memory layout.
- **ROP Chain Construction and Execution:** Crafting a fake control structure that includes ROP gadgets and shellcode, ultimately redirecting execution.

The end goal is to hijack execution in the browser’s process space, forming a critical building block for remote code execution (RCE) when combined with further exploitation steps (such as sandbox escape routines). This chain was specifically designed for educational purposes within a CTF context.

---

## Technical Breakdown

### Vulnerability Nature

**CVE-2020-6465** arises from a flaw in how Chrome handles certain Mojo interfaces and memory allocation routines. The asynchronous operations and improper management of freed memory allow an attacker to combine LFH manipulations and Mojo leaks to create a controlled memory corruption scenario. This corruption is then used to assemble a ROP chain that ultimately bypasses sandbox restrictions.

### Key Components of the Exploit Chain

1. **LFH-Style Allocation/Freeing:**
   - **Functions:** `allocateLFH_Win(src)` and `freeLFH_Win(iframe)` use iframes to simulate low fragmentation heap (LFH) behavior.  
   - **Purpose:** These routines groom the heap to create predictable allocation patterns that can later be exploited.

2. **Mojo Interface Manipulation:**
   - **sendPtr():** Establishes a Mojo message pipe by binding distinct endpoints to internal services (e.g., a Distiller JavaScript Service and a custom “PWN” interface).
   - **getFreedPtr():** Uses a MojoInterfaceInterceptor to detect and capture an interface request. It waits until a controlled free occurs, then wraps the leaked handle to provide a pointer that can be used for further exploitation.
   
3. **Custom Allocation for Heap Spraying:**
   - **getAllocationConstructor():** Sets up an allocation routine using `Mojo.createDataPipe()` and the BlobRegistry interface.  
   - **Capabilities:** Provides a controlled environment for “malloc”, “free”, and direct memory reads (via data pipes), allowing for precise heap spraying.
   
4. **Heap Spray and ROP Chain Construction:**
   - **Payload Assembly:** The `trigger(oob)` function builds a large ArrayBuffer payload that is filled with:
     - Gadget addresses (calculated from a provided base and offsets)
     - A block of custom shellcode
     - Repeated patterns to enforce a specific memory layout
   - **Objective:** Duplicate this payload across the heap so that when a leaked pointer is obtained (via `getFreedPtr()`), the overwritten memory leads the execution flow into the ROP chain.

### Exploitation Flow

1. **Heap Grooming:**  
   LFH-style allocations using iframes are created and freed. This helps ensure the existence of a vulnerable memory layout when the exploit chain is triggered.

2. **Pointer Leak via Mojo:**  
   The exploit uses `sendPtr()` and `getFreedPtr()` to capture a pointer from a freed object. This pointer is crucial for redirecting control flow in later stages.

3. **Payload Deployment via Heap Spray:**  
   A large ArrayBuffer is crafted with a detailed structure encompassing:
   - Critical gadget addresses (calculated relative to the base address)
   - Padding and filler instructions (including NOPs)
   - A legitimate shellcode block that demonstrates potential payload execution.
   
   The payload is then sprayed across the heap using multiple allocations, increasing the likelihood that a freed pointer will point into our controlled region.

4. **ROP Chain Execution:**  
   Finally, methods on the intercepted interface (e.g., `webRtcEventLogWrite` and `handleDistillerOpenSettingsCall`) are invoked to write the crafted overwrite payload. This triggers the redirection of execution into our ROP chain, leading to a sandbox bypass.

---

## Impact and Mitigation

- **Security Impact:**  
  In vulnerable versions of Chrome, this exploit chain can lead to complete sandbox escape. When integrated with further payloads, this primitive could ultimately enable remote code execution.
  
- **Mitigation:**  
  Google patched this vulnerability in updated versions of Chrome by improving memory management and in-depth validation of Mojo and allocation routines. Ensuring that all systems run updated browsers is the primary defense against this class of exploit.

---

## Conclusion

The CVE-2020-6465 exploit chain showcases how several advanced techniques—memory grooming, IPC abuse via Mojo, precise heap spraying, and ROP chain construction—can be combined to bypass robust security mechanisms like sandboxing in modern browsers. Our PoC, represented by the annotated `sbx.js` file and its companion infrastructure, is a testament to the sophistication required in contemporary exploitation and offers invaluable insights for both defenders and attackers in a controlled CTF environment.

---

## References

- [Google Threat Analysis Group (TAG) Blog](https://blog.google/threat-analysis-group/new-campaign-targeting-security-researchers/)
- Internal vulnerability analysis of CVE-2020-6465.
- Research on LFH exploitation and Mojo interface vulnerabilities in Chrome.

---

*Note: This exploit is provided solely for research, educational, and CTF purposes. Unauthorized use or deployment against systems without explicit permission is strictly prohibited.*