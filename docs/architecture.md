# Architecture

The engine installs its hooks in two phases. The phases serve different
purposes and are executed in a fixed order. This page documents that
order, why it exists, and the constraints it imposes on forking the
engine or adding modules.

---

## Two-phase hook installation

### Phase 1 — Framework (awaited)

Every module that targets an Android framework / bootclasspath class
(`Build`, `TelephonyManager`, `PackageManager`, `Settings`,
`NetworkInterface`, `SystemProperties`, `ContentResolver`, and so on)
installs inside a single `Java.performNow()` block.

`rpc.exports.init()` returns a **Promise** that resolves when that block
completes. Gadget's Script interaction mode waits for `init()` to
return, or for a returned Promise to resolve, before it releases the
host app's entrypoint.

This is what guarantees every framework-level hook is active before any
app code — including a static initializer — runs. Without it, an early
static initializer could read a real value (e.g. `ANDROID_ID` via
`Settings.Secure`) before the corresponding hook is installed, and the
spoofed value would never be observed.

**Why `Java.performNow()` and not `Java.perform()`.** `perform()`
defers its callback until the app's own classloader becomes available.
That happens only once app startup proceeds. But app startup is exactly
what the returned Promise is blocking. Using `perform()` here would
produce a deadlock that surfaces as an ANR ("failed to complete
startup"). `performNow()` executes immediately without the classloader
dependency, which is the documented choice for callers that do not need
app-specific classes.

Every module installed in this phase touches only framework classes —
none of them require the host app's own classloader.

### Phase 2 — Deferred (non-blocking)

When `javaHooksEnabled` is `true`, the config-driven `javaHooks` array installs in a separate
`Java.perform()` call. These hooks target the target app's own classes,
which may not be loaded when `init()` runs.

Each entry retries up to 10 times at 500 ms (up to ~5 seconds) via
`setTimeout`, so the app's entrypoint is never blocked on the retry
loop. A hook whose class never loads within the retry window is logged
as a failure and dropped — the rest of the engine continues normally.

The split is deliberate. Framework modules can and should block
startup, because they must be active before any app code runs.
App-class modules cannot block startup, because their target classes do
not exist yet — they load later, as the app executes. Deferring them
into a retry loop is the only correct option.

---

## Why SSL runs last

The apply order in `init()` places `applySslPinningBypass()` after
`applyNativePatches()`:

```
... → applyNativeHooks() → applyNativePatches() → applySslPinningBypass()
```

Two mechanisms operate on the same native address space:

- **`Interceptor.attach()`** (used by the SSL module's Flutter / BoringSSL
  layer) allocates a small executable **trampoline** stub in memory near
  the hooked address. Frida does this internally; it is not visible to
  the script.
- **`Memory.patchCode()`** (used by `nativePatches`) writes raw
  instruction bytes at a user-specified address.

The two do not coordinate. If a patch's target range happens to overlap
a trampoline that was just allocated, the patch overwrites the
trampoline's bytes. The next time the hooked function is called,
execution jumps into a corrupted stub — the app crashes with SIGSEGV.

Running `nativePatches` first claims its byte ranges while the address
space is clean. The SSL module's trampoline allocator then finds fresh
memory outside those ranges.

### The general rule

This hazard is not specific to SSL or to Flutter. It applies to **any**
native `Interceptor.attach()` hook that installs before a
`Memory.patchCode()` write.

On the engine's current install order, the SSL module is the only
native `Interceptor.attach()` that runs after `nativePatches`. If you
fork the engine and add more native-interception modules, install them
after `nativePatches` too. If a module must install earlier, verify that
its trampolines do not land inside any patched range.

**Do not reorder.**

---

## Adding a module

The conventions below apply when extending the engine. They are the same
conventions the existing 21 modules follow.

**Register a flag.** Declare a module-level `let` variable at the top of
`engine.js`, with a JSDoc comment describing its purpose and its
parameter-key override. Default is `false` unless the module is meant to
run unconditionally.

**Add an `apply*()` function.** Follow the existing pattern:

- Wrap the top-level function body in `try/catch`.
- Wrap every individual hook install in its own `try/catch` — a failure
  on one overload must not abort the rest.
- Wrap every hook body in `try/catch` — a failure inside a hooked call
  must not propagate into the host app.
- Log install events at `logI`, per-call events at `logD`, recoverable
  issues at `logW`, and fatal errors at `logE`.

**Track applied hooks.** Push every resolved overload target into an
`applied*Hooks` array. Reversion uses `target.implementation = null`
(Frida's documented sentinel for restoring the original), not a captured
snapshot of the prior implementation. Capturing
`overload().implementation` before overwriting it is unreliable — Frida
may return the same cached wrapper object on repeated `overload()`
calls, in which case reading `.implementation` after overwriting
returns the hook, not the original.

**Add a `revert*()` function.** Iterate the tracking array, set each
target's `.implementation` to `null`, and clear the array. For
`Interceptor.attach()`-style native hooks, call `listener.detach()`. For
`Memory.patchCode()` writes, restore the captured original bytes.

**Wire the flag into `init()`.** Add a `resolve*()` call for the flag
and, if applicable, its companion value object(s). Add the `apply*()`
call inside the `Java.performNow()` block in the position that respects
any ordering constraints (see [Why SSL runs last](#why-ssl-runs-last)).

**Wire the `revert*()` into `dispose()`.** Gate it on the same flag the
`apply*()` call is gated on.

**Fail-safe by default.** A wrong-typed value falls back to the source
default with a warning. A malformed array entry is caught per-entry
without affecting other entries.

For the concrete steps of compiling a modified `engine.js` into a
Gadget-loadable agent, see
[Installation → Compiling Your Own Agent](installation.md#compiling-your-own-agent).

---

## Related pages

- [Module Limits](limits.md) — open vs. closed value maps and platform boundaries
- [Modules](modules.md) — per-module description and mini config
- [Installation](installation.md) — setup for container, repack, and CLI modes
- [Contributing](contributing.md) — code style and how to add a module