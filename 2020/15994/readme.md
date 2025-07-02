# CVE-2020-15994 – WebAssembly instantiateStreaming use-after-free in Chrome

## Overview

This vulnerability existed in Google Chrome prior to version 85.0.4183.121. It allows a JavaScript attacker to exploit a **use-after-free condition** during WebAssembly streaming instantiation. The issue arises when a specially crafted `importObject` triggers a fetch abort while Chrome is still parsing and validating the WebAssembly binary. The resulting memory corruption may lead to remote code execution (RCE) within the browser context.

This PoC was used in the wild by North Korean state-sponsored actors in a campaign targeting security researchers, as detailed in Google TAG's [January 2021 disclosure](https://blog.google/threat-analysis-group/new-campaign-targeting-security-researchers/).

---

## Technical Breakdown

### Root Cause

- The bug stems from V8’s failure to correctly handle the interaction between:
  - `WebAssembly.instantiateStreaming()`
  - A getter on `importObject.env`
  - An aborted fetch mid-parsing
- During instantiation, Chrome attempts to read `importObject.env`.
- A malicious getter for `env` triggers `AbortController.abort()`, prematurely cancelling the fetch.
- Chrome proceeds to use memory tied to the now-aborted and freed fetch, resulting in a use-after-free.

### Exploitation Flow

1. **Setup**: A minimal valid WASM module is created and served using a Blob URL.
2. **Crafted importObject**: `env` is defined using a getter that aborts the fetch when accessed.
3. **Trigger**: Chrome calls `importObject.env`, triggering the getter → aborting fetch.
4. **Vulnerability**: Memory used by the WASM parser is prematurely freed and reused.
5. **Outcome**: On vulnerable versions of Chrome, this can lead to memory corruption or crashes. With further exploitation, arbitrary code execution is possible.

---

## PoC Notes

- The included PoC uses `AbortController` and a dynamic `importObject` to time the abort precisely.
- The WebAssembly module is benign and minimal—no shellcode is present.
- The exploit demonstrates a crash trigger, not a full RCE chain (e.g., no sandbox escape is included in this file).
- Compatible with Chrome versions 85.0.4183.120 and below.

---

## Mitigation & Patch

Google patched the vulnerability in:
- **Chrome version 85.0.4183.121** (September 2020)
- The patch ensures that WASM instantiation aborts cleanly and securely when a streaming source is interrupted.

Forensic indicators and campaign insights are available in Google TAG’s official post.

---

## References

- [Google TAG – January 2021 Threat Report](https://blog.google/threat-analysis-group/new-campaign-targeting-security-researchers/)
- [V8 Patch](https://chromium-review.googlesource.com/c/v8/v8/+/2390711)
- Chromium Bug Tracker: Issue 1131073 (restricted at the time of disclosure)