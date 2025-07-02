# CVE-2025-6554: V8 TurboFan JIT Optional Chaining Type Confusion

> **Status:** Proof-of-Concept (Educational, Incomplete)  
> **Severity:** High (Type Confusion → OOB R/W → Code Execution)  
> **Component:** V8 JavaScript Engine (TurboFan JIT)  
> **Tested On:** Chrome 108.x – 112.x (Linux x64)  
> **CVE Identifier:** CVE-2025-6554

---

## 1. Executive Summary

A JIT compiler optimization bug in V8’s TurboFan engine leads to a type confusion when a function is warmed with “packed” float arrays and later invoked on a “holey” array. This discrepancy between the compiler’s type assumptions and the actual array layout can be abused to achieve out-of-bounds (OOB) read/write primitives, paving the way to arbitrary code execution in the renderer process.

---

## 2. Vulnerability Class

- **Root Cause:** JIT’s Inline Cache (IC) specialization assumes element kind stability  
- **Trigger:** Optional chaining (`.?[]`) coupled with holey vs. packed array transitions  
- **Consequence:** Treating a `double`-backed array slot as a pointer slot (and vice versa)  
- **Attack Surface:** Renderer process, remote attacker on a crafted webpage  

---

## 3. Affected Versions

| Version Range         | Status        |
|-----------------------|---------------|
| Chrome ≤ 112.0.5615.x | Vulnerable    |
| Chrome ≥ 113.0        | Patched       |

---

## 4. Technical Details

### 4.1 TurboFan JIT & Inline Caches

1. **JIT Warmup**  
   - TurboFan observes repeated calls to a function, collects type feedback,  
     and emits optimized machine code assuming stable types.

2. **Packed vs. Holey Arrays**  
   - **Packed Float Array** (`[1.1, 2.2, 3.3]`):  
     all elements are `double`-sized and densely packed.  
   - **Holey Float Array** (`[1.1, , 3.3]`):  
     a “hole” forces V8 to switch internal array representation; it may  
     store element kinds differently (tagged pointers vs. unboxed doubles).

3. **Type Confusion Window**  
   - After JIT warmup on a packed array, the JIT-generated code inlines  
     a `LoadElement` that assumes float access.  
   - Invoking the same code on a holey array leads to loading a 
     pointer-sized slot but interpreting it as an unboxed `double` (or vice versa).

### 4.2 Memory Layout & OOB Potential

- Misinterpreting a pointer as a floating-point value leaks heap addresses.  
- Conversely, treating a `double` cell as a pointer slot allows overwriting  
  typed slots, breaking safety checks and enabling OOB writes.

---

## 5. Proof-of-Concept Outline

> **Note:** This outline is *educational only*. All active exploit steps and shellcode injection are omitted.

1. **Define the Victim Function**  
   - A tiny function using optional chaining to access `arr?.[0]`.  
   - This triggers an IC transition on first calls.

2. **JIT Warmup Phase**  
   - Repeatedly call the victim with a **packed** float array.  
   - Achieve type-feedback stabilization: the compiler emits float-only loads.

3. **Type Confusion Trigger**  
   - Invoke the same function with a **holey** float array.  
   - JIT code still uses float-load path on a pointer-backed slot → corruption.

4. **Leaking an Address**  
   - Read back the corrupted output (interpreted as a `double`) → raw pointer value.  
   - Convert that `double` into an integer to compute base addresses.

5. **Building Arbitrary Read/Write**  
   - Craft a fake JSArray or JSObject in memory (via controlled backing store).  
   - Poison its `elements` or `butterfly` pointer to point at arbitrary addresses.  
   - Expose `read64(addr)` and `write64(addr, value)` helpers.

6. **Gaining RWX Memory**  
   - Instantiate a minimal WebAssembly module (e.g., `[0x00,0x61,0x73,0x6d…]`).  
   - Extract its backing buffer, which is marked RWX by the OS.  
   - Use `write64` to copy shellcode bytes into that region.

7. **Code Execution (Omitted)**  
   - Overwrite a function pointer or return address to jump into your shellcode.  
   - Drop into a system call or escape sequence.

---

## 6. Mitigation & Recommendations

- **Patch Inline Cache Behavior:** Invalidate ICs when an array’s element kind changes.  
- **Safer Array Transitions:** Introduce intermediate checks before JIT float loads.  
- **Audit Optional Chaining Paths:** Ensure all IC-driven opcodes guard against holes.

---

## 7. References

1. “V8 Developer Guide: Inline Caches & Optimizing Compiler”  
2. CVE-2022-1096 – V8 TurboFan type confusion via optional chaining  
3. CVE-2021-21220 – Elements kind transition bug in V8  
4. “WebAssembly: Achieving RWX Memory” – Chrome Security Team blog  

---
