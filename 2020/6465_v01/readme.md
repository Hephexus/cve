# CVE-2020-6465 – Chrome Sandbox Bypass Exploit Chain

## Overview

This exploit chain demonstrates a sophisticated Chrome sandbox bypass using advanced heap manipulation and ROP techniques. It spans several stages:
- **Global Setup & ROP Gadget Declarations:**  
  The exploit begins by declaring a vast array of global variables, candidate offsets for ROP gadgets, and handles for different WebAssembly components. These variables hold critical addresses (such as VTable pointers) and offsets used later in the exploit.
  
- **Heap Grooming & LFH Manipulation:**  
  Using functions like `gc()` and `make_or_fill_LFH()`, the exploit coerces the browser into a predictable Low Fragmentation Heap (LFH) state. This controlled environment increases the chance that freed memory chunks will be reallocated in a manner favorable to the attacker.
  
- **VTable Leakage & Overwrite Phases:**  
  Two distinct phases are used:
  - **Vtable Leak Phase:** The function `vtable_leak()` leverages a crafted import object (prepared with `make_import_object_info()`) and a WASM module (constructed from benign WASM code) to leak critical memory addresses.  
  - **Vtable Overwrite Phase:** The exploit then resets the import object (via `make_import_object_oob()`), reassigns a different WASM module, and triggers an out-of-bounds write. This overwrite redirects execution flow by replacing a VTable pointer with a chain of controlled gadget addresses.
  
- **ROP Chain Construction & Final Exploitation:**  
  Throughout the payload, ROP gadgets are selected from predefined arrays and combined into a chain. The chain sets up necessary parameters, performs register moves, and finally pivots the stack (using gadgets like `jmp rsp`) to transfer control to the injected shellcode. The shellcode itself is injected and carefully aligned with the manipulated heap via extensive heap spraying, ensuring that when control is transferred, it executes in the attacker’s controlled environment.

- **Orchestration & Flow Control:**  
  Functions like `free_LFH_End()`, `oob_write()`, and `info_leak()` coordinate the phase transitions. The main entry point, `_start()`, initializes variables, checks for environment compatibility (e.g. via `selectChromeVersion()`), and triggers the initial heap-filling functions to groom memory for exploitation.

## Technical Breakdown

### 1. Global Declarations and ROP Gadget Setup

- **Global Variables:**  
  Variables such as `wasmCode_Info`, `sprayArr_Info`, `global_Arr`, and others hold key data buffers, pointers, and spray arrays.
  
- **ROP Gadget Offsets:**  
  Arrays like `mov_rsp_rax_Offset_Arr`, `pop_r8_Offset_Arr`, and others list candidate gadget offsets. These offsets are later resolved relative to a base leaked from a VTable pointer, ensuring that gadget addresses are valid for the target process.

### 2. Heap Grooming and LFH Manipulation

- **Garbage Collection & Allocation:**  
  The function `gc()` aggressively allocates large ArrayBuffers and repeatedly creates DOM elements to trigger garbage collection, forcing a predictable heap state.
  
- **LFH Strategies:**  
  Helper functions such as `allocateLFH_Win()` and related routines use iframes to influence the LFH state. This grooming is later vital for ensuring that freed memory lands predictably in attacker-controlled areas.

### 3. Information Leakage and Import Object Manipulation

- **Vtable Leakage:**  
  The `info_leak()` function reads memory from a WASM instance’s exported memory. It extracts a VTable pointer, then validates the leak by checking a masked pointer value. If successful, it computes a base address and derives the addresses for necessary ROP gadgets.
  
- **Import Object Construction:**  
  Two methods—`make_import_object_info()` and `make_import_object_oob()`—prepare specialized import objects:
  - The **info** type inserts benign globals to induce information leakage.
  - The **OOB** (out-of-bounds) version injects controlled globals that serve as container for the ROP chain. The globals at critical indices (e.g., near index 0x3E) are populated with gadget addresses and critical parameters needed for transitioning control.

### 4. Shellcode Injection and ROP Chain Execution

- **Shellcode Payload:**  
  A large Uint8Array (`shellCode`) is constructed by concatenating byte sequences:
  - It starts with marker patterns (0xAA, 0x55) to provide alignment.
  - It includes a `mov rax, imm64` instruction that embeds the target WebAudioMediaStreamSource VTable.
  - This is followed by a series of instructions (using opcodes for data movement, register manipulation, and stack adjustments) that set up the ROP chain.
  
- **Heap Spray:**  
  The payload is duplicated across multiple allocations (via functions such as spray) to ensure that the ROP chain is reliably placed in memory.

### 5. Phase Management and Final Execution

- **Phase Functions:**  
  - `free_LFH_End()` controls the transition between exploit phases by checking `exploit_Step` and scheduling the next action (whether leaking or overwriting memory).
  - `oob_write()` fires when the out-of-bounds write is performed and stops the heap spray once success is detected.
  - `vtable_leak()` and `vtable_overwrite()` are the pivotal phase transitions; they swap out the import objects and trigger WASM instantiation to tip the memory state over into exploitation.
  
- **Exploit Startup:**  
  The entire chain is initiated by `_start()`, which calls initialization routines, checks compatibility via `selectChromeVersion()`, and begins the LFH allocation routine with `make_or_fill_LFH(0x20)`.

## Exploitation Flow Summary

1. **Initialization and Memory Grooming:**  
   The exploit begins by allocating many objects to shape the heap (using LFH strategies) and triggering garbage collection events.

2. **Vtable Leak Phase:**  
   A benign WASM module, combined with a specially crafted import object, leaks a VTable pointer. This leak provides the base address for calculating ROP gadget addresses.

3. **Vtable Overwrite Phase:**  
   The import object is reconfigured with controlled globals to perform an out-of-bounds write. This overwrites entries in the VTable (or neighboring control structures), setting the stage for redirecting execution.

4. **Heap Spray and ROP Chain Construction:**  
   A carefully crafted shellcode payload is built and sprayed across the heap. This ROP chain includes instructions to adjust memory protections, pivot the stack, and ultimately execute injected code.

5. **Final Trigger and Execution Handoff:**  
   Once the target pointers are overwritten and the gadget chain set, an interface call (via WASM exploit functions) triggers the chain. Control is then transferred into the shellcode, achieving the sandbox bypass.

## Impact & Mitigation

- **Impact:**  
  Successfully exploiting this chain can bypass Chrome’s robust sandbox, enabling further exploitation (such as arbitrary code execution). As the chain leverages numerous low-level techniques—from heap grooming to precise ROP gadget resolutions—it demonstrates the high level of sophistication possible in modern browser attacks.
  
- **Mitigation:**  
  Google patched this vulnerability in Chrome updates by improving memory management during WASM instantiation, better handling of Mojo interfaces, and more robust validations during heap operations. Users should always run the latest, patched version of Chrome to remain protected.

## Conclusion

This exploit chain, CVE-2020-6465, combines multiple advanced techniques into a cohesive attack against Chrome’s sandbox. By manipulating low-level heap structures, leveraging information leaks, and constructing a powerful ROP chain, it illustrates how seemingly disparate vulnerabilities can be chained together. While the PoC demonstrates a crash and controlled memory overwrite, it lays the groundwork for a full remote code execution chain when combined with further sandbox escapes. This detailed breakdown not only serves as a CTF challenge but also provides valuable insight into modern exploitation techniques.

## References

- [Google Threat Analysis Group Blog – New Campaign Targeting Security Researchers](https://blog.google/threat-analysis-group/new-campaign-targeting-security-researchers/)
- Research on LFH manipulation and Mojo interface exploitation in Chrome.
- Internal analysis of exploit techniques using WebAssembly and heap spraying.

*Note: This exploit is provided strictly for educational, research, and CTF use. Unauthorized use is both illegal and unethical.*