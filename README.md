# Frida Hook Engine

> A configuration-driven instrumentation engine for Frida on Android.   
> 21 hook modules behind one JSON config — SSL pinning bypass, device   
> spoofing, package hiding, native hooking, and more.

[![License](https://img.shields.io/badge/license-Apache--2.0-lightgrey.svg)](LICENSE)
[![Frida](https://img.shields.io/badge/Frida-17.x-green.svg)](https://frida.re)
[![Platform](https://img.shields.io/badge/platform-Android%20ARM64-orange.svg)]()
[![Modules](https://img.shields.io/badge/modules-21-blueviolet.svg)]()

---

## Fastest path

If `libfrida-gadget.so`, `libfrida-gadget.config.so`, and
`libfrida-gadget.script.so` are already embedded or injected into your
target app, no code, no build pipeline, and no command line are needed.

`libfrida-gadget.config.so` is a plain JSON text file despite its `.so`
extension. Open it in any text editor:

1. Find the module flag you want to enable.
   ```jsonc
   "sslPinningBypassEnabled": false,
   ```
2. Change `false` to `true`.
   ```jsonc
   "sslPinningBypassEnabled": true,
   ```
3. Save the file.
4. Restart the target app.

That is the entire workflow. The engine reads the config on every app
launch and enables whatever you set to `true`.

**Using a different mode?** The `libfrida-gadget.config.so` file applies
only to Gadget Script mode. For Frida CLI (rooted spawn/attach), edit
the flags at the top of `engine.js` directly — no config file exists in
that mode. For Gadget Listen mode, pass parameters via
`rpc.exports.init()` from a live controller. Both are covered in
[Quick start](#quick-start).

---

## Overview

Frida Hook Engine is a single-file instrumentation script bundling 21
independent modules behind one configurable surface. Every module is
toggled by a boolean; every value is tunable by a JSON edit.

Three deployment modes, one codebase:

| Mode | Who it is for | How to load it | How to configure it |
|---|---|---|---|
| **Gadget — Script** | Embedded, non-root use | `agent.js` via `libfrida-gadget.config.so` | Edit `libfrida-gadget.config.so` |
| **Frida CLI — attach** | Rooted devices, live debugging | `frida -U -f <pkg> -l engine.js` | Edit flag defaults in `engine.js` |
| **Gadget — Listen** | Pre-built agent, live controller | Gadget Listen mode + Frida REPL | Call `rpc.exports.init()` from the REPL |

No root is required for the Gadget paths. On non-root devices,
[`frida-bridge`](https://github.com/muhammadrizwan87/frida-bridge) loads
the gadget from a container / virtual space without modifying the target
APK.

---

## Quick start

Three setup paths. Each is a one-time configuration.

### Path A — Container / virtual space (no root, no repack)

Uses [`frida-bridge`](https://github.com/muhammadrizwan87/frida-bridge).

1. Set up `frida-bridge` inside your container — follow the setup steps
   in frida-bridge's own README.
2. Clone the target app inside the container.
3. Create `/data/data/<target.pkg>/files/frida/`.
4. Place three files in that folder:
   - `libfrida-gadget.so` — from the engine release ZIP or [Frida releases](https://github.com/frida/frida/releases) for your ABI
   - `libfrida-gadget.config.so` — from the engine release ZIP
   - `libfrida-gadget.script.so` — from the engine release ZIP
5. Run the target app inside the container.

Full walkthrough: [Installation → Path A](docs/installation.md#path-a--container--virtual-space).

### Path B — Repack the APK (no root, one-time rebuild)

1. Decompile the APK with **Apktool** or **MT Manager**.
2. Copy the three engine files into `lib/arm64-v8a/`.
3. Add `System.loadLibrary("frida-gadget")` to the app's
   `Application.onCreate()`.
4. Rebuild the APK and sign it. Any signing tool works —
   [`KeySigner`](https://github.com/muhammadrizwan87/keysigner) is one
   option among several. Then install.

32-bit target? Use `lib/armeabi-v7a/`. The SSL native layer requires
ARM64; the other 20 modules work on any ABI.

Full walkthrough: [Installation → Path B](docs/installation.md#path-b--repack-the-apk).

### Path C — Frida CLI (rooted or emulator)

```bash
git clone https://github.com/muhammadrizwan87/frida-hook-engine
cd frida-hook-engine
frida -U -f com.example.app -l engine.js
```

Source-level defaults apply. To change behavior without a config file,
edit the flags at the top of `engine.js`.

Full walkthrough: [Installation → Path C](docs/installation.md#path-c--direct-load-via-cli).

---

## How configuration works

The engine ships as three coordinated files:

| File | Purpose | Who edits it |
|---|---|---|
| `engine.js` | Source script (plain JavaScript) | Advanced users, contributors |
| `agent.js` | Pre-compiled bundle for Gadget | Maintainers only |
| `config.json` | Runtime parameters for the agent | End users |

Priority rule:

```
config.json value (if key present)
  overrides
engine.js source-level default
  always present as fallback
```

A missing key uses the source default. A wrong-typed key is logged with a
warning and the source default is used. A malformed config never breaks
the engine.

Full reference: [Configuration](docs/configuration.md).

---

## Enabling modules

The `*Enabled` flag must be `true` for a module to run. Value objects
(like `geoSpoofValues`) only take effect when their companion flag is
`true` — with the flag `false`, they are ignored and the module does not
run at all.

**Enable one module with defaults:**

```jsonc
"sslPinningBypassEnabled": true
```

**Enable multiple modules:**

```jsonc
"buildPropSpoofEnabled": true,
"systemPropertySpoofEnabled": true,
"deviceIdSpoofEnabled": true,
"deviceIdSpoofUseRandom": true,
"hardwareFeatureSpoofEnabled": true
```

**Enable a module and override its values.** The flag must be `true`
first; only then does the value object apply.

```jsonc
"geoRestrictionBypassEnabled": true,
"geoSpoofValues": {
  "operatorName": "T-Mobile",
  "plmn": "310260",
  "countryIso": "us"
}
```

Only list what you want to change. Everything else falls back to its
source default.

**Using Frida CLI or Listen mode instead of Gadget Script?** Those modes
have no config file. For CLI attach/spawn, source-level defaults apply —
edit the flags at the top of `engine.js` to change behavior. For Listen
mode, pass parameters via `rpc.exports.init()` from a live controller.

---

## Modules

21 modules. Every flag is optional; every module is off by default.

| Flag | Purpose |
|---|---|
| `sslPinningBypassEnabled` | Bypass TLS certificate pinning (Java + Flutter native). ⚠️ *beta* |
| `vpnProxyBypassEnabled` | Hide VPN and proxy state from Android and JVM APIs |
| `installerSpoofEnabled` | Report Play Store as the app installer |
| `adbDevSettingsBypassEnabled` | Report ADB and Developer Options as disabled |
| `mockLocationBypassEnabled` | Hide mock-location usage |
| `autoTimeSpoofEnabled` | Force automatic clock and timezone |
| `pairipLicenseBypassEnabled` | Neutralize Google Play's PairIP license check |
| `flagSecureBypassEnabled` | Allow screenshots and screen recording |
| `geoRestrictionBypassEnabled` | Spoof carrier, PLMN, and country |
| `localeSpoofEnabled` | Spoof language, country, and timezone |
| `suspiciousPackageSpoofEnabled` | Hide listed packages (blocklist) |
| `installedPackageSpoofEnabled` | Make listed packages appear installed (whitelist) |
| `deviceIdSpoofEnabled` | Spoof IMEI, MEID, ICCID, IMSI, MAC, advertising ID |
| `buildPropSpoofEnabled` | Mutate `android.os.Build` fields to a device profile |
| `systemPropertySpoofEnabled` | Hook `SystemProperties.get()` for raw `ro.*` / `qemu.*` reads |
| `hardwareFeatureSpoofEnabled` | Force `hasSystemFeature()` to report listed features |
| `contentProviderSpoofEnabled` | Intercept direct `ContentResolver.query()` / `call()` |
| `javaHooksEnabled` | Enable config-driven Java / Kotlin method hooks |
| `nativeHooksEnabled` | Hook native (.so) functions |
| `nativePatchesEnabled` | Patch raw instruction bytes at an address |
| `registerNativesLogEnabled` | Log every `RegisterNatives` call at runtime |

Per-module details: [Modules](docs/modules.md).

---

## Example configurations

Every module is independent. Enable only what your target requires —
none of the combinations below are required. They are common groupings,
not dependencies.

**Emulator detection bypass:**

```jsonc
"buildPropSpoofEnabled": true,
"systemPropertySpoofEnabled": true,
"deviceIdSpoofEnabled": true,
"deviceIdSpoofUseRandom": true,
"hardwareFeatureSpoofEnabled": true
```

**MITM proxy interception:**

```jsonc
"sslPinningBypassEnabled": true,
"vpnProxyBypassEnabled": true
```

**PairIP-protected apps:**
> NOTE: not a paid/commercial license bypass. This only unblocks a   
> free app's client-side PairIP check inside a virtualized/emulated   
> research environment.

```jsonc
"pairipLicenseBypassEnabled": true,
"installedPackageSpoofEnabled": true,
"installerSpoofEnabled": true
```

**Developer Options / ADB detection:**

```jsonc
"adbDevSettingsBypassEnabled": true,
"mockLocationBypassEnabled": true,
"contentProviderSpoofEnabled": true
```

**Geo-restricted content:**

```jsonc
"geoRestrictionBypassEnabled": true,
"localeSpoofEnabled": true
```

Module dependency details: [Module Pairing](docs/pairing.md).

---

## Verifying it works

```bash
adb logcat -s FridaHookEngine:V
```

Log levels:

| Level | Emitted for |
|---|---|
| `logD` | Per-call debug output |
| `logI` | Module install events |
| `logW` | Recoverable warnings |
| `logE` | Fatal errors |

Set `"debugLog": false` in the config to silence everything.

---

## Troubleshooting

Four most common issues.

**`ClassNotFoundException` with `DexPathList[[directory "."], ...]`**
The class is being resolved before the app classloader is available. Move
`System.loadLibrary("frida-gadget")` into `Application.onCreate()`.

**Malformed config value produces a warning but no change**
Working as designed. The warning identifies the key and expected type.
Correct the value in `config.json`.

**Flutter native SSL bypass not active**
Either the target is not ARM64, or `libflutter.so` is not loaded yet. The
Java layer still covers the app's own TLS calls.

**Target app is packed with Google PairIP protection**
`pairipLicenseBypassEnabled` neutralizes only the license-check client,
not PairIP's vm packing layer. That layer monitors Frida's Java bridge and
terminates the app the moment any Java API fires (`Java.use`,
`Java.perform`, `.implementation =`). The engine itself uses Java APIs
during `init()`, so on a PairIP-packed target it crashes before any hook
takes effect. Native hooks are not a workaround — the engine cannot
start.

Full list: [Troubleshooting](docs/troubleshooting.md).

---

## Documentation

| Page | Covers |
|---|---|
| [Installation](docs/installation.md) | Setup for container, repack, and CLI modes |
| [Configuration](docs/configuration.md) | Full parameter reference and config model |
| [Modules](docs/modules.md) | Per-module description and mini config |
| [Module Pairing](docs/pairing.md) | Which modules depend on or feed into others |
| [Module Limits](docs/limits.md) | Open vs. closed value maps and platform boundaries |
| [Advanced Usage](docs/advanced-usage.md) | Custom Java hooks, native hooks, native patches |
| [Architecture](docs/architecture.md) | Two-phase hook installation and ordering rules |
| [Troubleshooting](docs/troubleshooting.md) | Common errors and how to resolve them |
| [Contributing](docs/contributing.md) | Code style and how to add a module |

---

## License

Apache-2.0. See [LICENSE](LICENSE).

---

## Credits

**Engine by:** MuhammadRizwan from India

**Companion projects:**

- [keysigner](https://github.com/muhammadrizwan87/keysigner) — APK signing tool
- [frida-bridge](https://github.com/muhammadrizwan87/frida-bridge) — native loader for container / virtual-space environments

Built on [Frida](https://frida.re) by Ole André Vadla Ravnås and contributors.