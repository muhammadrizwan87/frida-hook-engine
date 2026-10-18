# Troubleshooting

Failure modes grouped by category: configuration, classloader, platform,
module, and target. Each entry states the symptom, the cause, and the
resolution.

For anything not covered here, capture logs first — most issues are
visible in the log output before they need deeper investigation.

---

## Getting logs

```bash
adb logcat -s FridaHookEngine:V
```

Every engine message is tagged `FridaHookEngine`. Levels:

| Level | Emitted for |
|---|---|
| `logD` | Per-call debug output |
| `logI` | Module install and revert events |
| `logW` | Recoverable warnings (wrong-typed config values, missing classes) |
| `logE` | Fatal errors |

Set `"debugLog": false` in `config.json` to silence `logD` and `logI`.
`logW` and `logE` are always emitted.

**Reporting an issue.** Include engine version, Frida version, target
package, the `parameters` subset in use, and a log excerpt covering the
window from app launch to the point of failure.

---

## Configuration issues

### A malformed config value produces a warning but no change

**Symptom.** The engine logs a warning naming the key and expected type,
but the value has no effect.

**Cause.** Working as designed. A wrong-typed config value falls back to
the source-level default instead of crashing the engine.

**Resolution.** Correct the value's type in `config.json`. The warning
identifies the key and the expected type — for example:

```
[init] parameters.debugLog expected boolean, got string — using default (true)
```

`boolean` parameters require a JSON `true` / `false`, not `"true"` /
`"false"`. `string` parameters require a JSON string, not a number.
`array<string>` parameters require a JSON array of strings, not a
single string.

---

## Classloader issues

### `ClassNotFoundException` with `DexPathList[[directory "."], ...]`

**Symptom.** The engine logs a `ClassNotFoundException` when resolving a
hook target. The class name is correct, but the class cannot be found.

**Cause.** The class is being resolved before the app's classloader is
available. This happens when the gadget loads earlier than
`Application.attachBaseContext()`.

**Resolution.**

- **Gadget is embedded in a repacked APK:** move
  `System.loadLibrary("frida-gadget")` into `Application.onCreate()` —
  see [Installation → Path B](installation.md#path-b--repack-the-apk).
- **The class loads later than the engine expects:** when `javaHooksEnabled` is `true`, `javaHooks` retries
  up to 10 times at 500 ms (≈5 seconds) via `setTimeout`. If the class
  still is not loaded in that window, the hook is dropped and logged as
  a failure. Increase `MAX_ATTEMPTS` in `applyHookWithRetry()` if a
  longer window is needed, or accept the hook failing and rely on the
  framework-level modules.

---

## Platform-specific limitations

### Android 17 (API 37+) — Build field writes fail with `IllegalAccessException`

**Symptom.** `buildPropSpoofEnabled` is set to `true`, but individual
`Build.*` field writes fail with `IllegalAccessException`.

**Cause.** ART on Android 17 restricts reflective writes to
`public static final` fields.

**Resolution.** No workaround is implemented. Fields fail per-field (each
write is independently caught and logged); the rest of the engine
continues normally. `systemPropertySpoofEnabled` still covers
`SystemProperties.get()` reads on affected devices. A target that reads
`Build.*` fields directly will not be spoofed on Android 17 without an
engine-level change.

---

## Module-specific issues

### Flutter native SSL bypass not active

**Symptom.** `sslPinningBypassEnabled` is set to `true`, the log does
not show the expected `[+] [Native] pair #...` install line, or the
target's TLS handshakes continue to fail behind an interception proxy.

**Cause.** One of two conditions:

- The target is not `arm64-v8a`. The native layer is ARM64-only.
- `libflutter.so` is not loaded in the process. The native layer is
  Flutter-specific; a non-Flutter app will not have it loaded.

**Resolution.**

- For a non-ARM64 target: the Java layer still covers the app's own TLS
  calls. Only the Flutter native layer is unavailable.
- For a non-Flutter app: the Java layer runs and covers the standard
  Android TLS stack (OkHttp, `SSLContext`, `HttpsURLConnection`, Network
  Security Config, TrustKit, Appmattus CT).

Check the log for one of these lines to confirm which case applies:

```
[*] libflutter.so not present, skipping native bypass
[-] [Native] Unsupported architecture: <arch> (ARM64 required)
```

---

## Target-specific challenges

### Frida detection present in the target app

**Symptom.** The app refuses to start, or terminates shortly after
launch, before any engine hook installs.

**Cause.** The target actively detects Frida. Common checks include:

- `frida` / `gum` strings in memory maps
- Frida's default port `27042`
- Thread names like `gum-js-loop`
- `/data/local/tmp/re.frida.server` remnants

The engine does not include a Frida-detection bypass. It assumes the
gadget has already loaded successfully and is running.

**Partial mitigation.** Renaming Frida's artifacts raises the detection
bar significantly against naive string-based checks (which most
commercial apps use):

- Rename `libfrida-gadget.so` to an innocuous name
- Set a custom `"name"` field in the gadget configuration
- Use a non-default port
- Rebuild the gadget with custom thread names

These defeat signature-based detection but not behavioral or timing-based
detection. A target that has been hardened against Frida specifically —
rather than only checking for the obvious strings — may still detect
the gadget at runtime.

**What the engine cannot do for you.** Bypass an app that has already
refused to run because it detected Frida. Detection bypass is a separate
problem from the hooks this engine installs.

### Target app is packed with Google PairIP protection

**Symptom.** With PairIP's vm packing layer active, the app terminates the
moment the engine's `init()` runs. No hook install logs appear.

**Cause.** `pairipLicenseBypassEnabled` neutralizes only the PairIP
**license-check client** — a single method on
`com.pairip.licensecheck.LicenseClient`. PairIP's **vm packing layer** is a
separate anti-tamper, anti-debug, and anti-Frida framework. It monitors
Frida's Java bridge and terminates the app on the first Java API call.

The engine uses Java APIs during `init()` (`Java.performNow()` runs
before any hook install). On a PairIP-packed target, the app terminates
before any hook — framework or native — has a chance to install. Native
hooks are not a workaround: the engine cannot initialize.

**Mitigation.** Renaming Frida's artifacts (see the previous entry) may
extend the window before detection, but does not remove the layer.
Comprehensive bypass requires reverse-engineering the specific PairIP
build in the target, which is out of scope for this engine.

If the target is PairIP-Licensed but **not** packed with the VM
packing layer — for example, an app that only uses the license-check
client — `pairipLicenseBypassEnabled` works normally. The distinction is
visible in the app's native libraries: a `.so` containing PairIP VM
bytecode and integrity-check routines indicates the vm packing layer; a
plain `libpairipcore.so` or no additional native layer suggests only the
license check.

---

## Related pages

- [Modules](modules.md) — per-module description and mini config
- [Module Limits](limits.md) — platform and coverage boundaries
- [Architecture](architecture.md) — two-phase hook installation and ordering rules
- [Configuration](configuration.md) — full parameter reference and config model