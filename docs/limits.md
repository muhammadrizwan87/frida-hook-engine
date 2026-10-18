# Module Limits

Two kinds of boundaries apply to the engine:

1. **Value-map boundaries** — which keys a value object accepts and what
   happens to unrecognized ones.
2. **Platform and coverage boundaries** — which Android surfaces a
   module hooks and which it does not.

Each is documented below. No module covers everything a well-written
detector could check; the limits below define the actual coverage so a
gap is predictable rather than surprising.

---

## Value-map boundaries

Value objects follow one of four schemas. Each schema's behaviour on
unrecognized keys is fixed.

| Schema | Modules | Unrecognized keys |
|---|---|---|
| **Closed-key flat map** | `geoSpoofValues`, `localeSpoofValues`, `buildPropSpoofValues`, `deviceIdSpoofValues`, `registerNativesLogLocator` | Logged and ignored |
| **Open-key flat map** | `systemPropertySpoofValues` | Accepted |
| **Nested map** | `contentProviderSpoofValues`, `installedPackageSpoofValues` | Accepted at both levels |
| **String array** | `suspiciousPackagesCustom`, `spoofedHardwareFeatures` | *(no keyed structure)* |

### Closed-key flat maps

Only the keys declared in the module's default object are accepted. An
unrecognized key is logged with a warning and ignored; the module's
default for that key is retained. A recognized key with a non-string
value is also logged and its default retained.

The closed key set is documented per module:

| Module | Fixed key set |
|---|---|
| `geoSpoofValues` | `operatorName`, `plmn`, `countryIso` |
| `localeSpoofValues` | `country`, `language`, `timezoneId` |
| `buildPropSpoofValues` | 15 `Build.*` fields (`manufacturer`, `model`, `brand`, `product`, `device`, `hardware`, `board`, `bootloader`, `host`, `id`, `fingerprint`, `tags`, `type`, `user`, `display`) + 4 `Build.VERSION.*` fields (`release`, `securityPatch`, `incremental`, `codename`) |
| `deviceIdSpoofValues` | `androidId`, `imei`, `meid`, `iccid`, `imsi`, `phoneNumber`, `wifiMac`, `bluetoothMac`, `advertisingId`, `internalIp` |
| `registerNativesLogLocator` | `symbolName`, `offset` |

### Open-key flat maps

Any string-valued key is accepted, in addition to the module's default
keys. A non-string value for any key is logged with a warning and that
key is skipped.

`systemPropertySpoofValues` is the only module that uses this schema,
because the key space is inherently unbounded — any `ro.*`, `persist.*`,
or `qemu.*` property name is a valid key.

### Nested maps

Two-level `{ outer: { inner: string } }` shape. Both levels are open:

- An outer key (authority or package name) that is not present in the
  defaults is accepted and treated as a new entry.
- An inner key that is not present in the defaults is accepted.
- An outer entry whose value is not an object is rejected with a warning
  and skipped; the rest of the map is unaffected.
- An inner entry whose value is not a string is rejected with a warning
  and skipped; the rest of that outer entry's map is unaffected.

Used by `contentProviderSpoofValues` (outer key = authority) and
`installedPackageSpoofValues` (outer key = package name).

### String arrays

An array in which every element is a string. A non-array value, or an
array containing a non-string element, is rejected with a warning and
the source default is retained.

### Array-of-objects parameters

`javaHooks`, `nativeHooks`, and `nativePatches` accept arrays of objects.
The resolver validates only that the parameter is an array; malformed
individual entries are caught per-entry by the apply function and do not
affect other entries. This is a deliberate fail-safe-per-item design.

---

## Platform and coverage boundaries

### SSL pinning — native layer

| Boundary | Detail |
|---|---|
| Architecture | ARM64 (`arm64-v8a`) only. Non-ARM64 targets skip the native layer silently — the Java layer still runs |
| Module | Only `libflutter.so`. The BoringSSL verify function is located by a version-agnostic heuristic scan (string-anchor + ADRP cross-reference + prologue scan) |
| Not covered | WebView traffic in a separate process (requires a second Frida session attached to the WebView provider process); Cronet / HTTP/3 (`org.chromium.net.X509Util`); manually implemented certificate-hash comparisons with no library |

### Build-prop spoofing

| Boundary | Detail |
|---|---|
| Fields excluded by design | `SDK_INT` (commonly gates the app's own code paths) and `SUPPORTED_32_BIT_ABIS` / `SUPPORTED_64_BIT_ABIS` / `SUPPORTED_ABIS` (spoofing risks crashing the app if it later loads a native library for an architecture the device does not actually have) |
| Platform restriction | Android 17 (API 37+) restricts reflective writes to `public static final` fields. On affected devices, field writes may fail per-field with `IllegalAccessException`; the failure is logged, and the rest of the engine continues normally. `systemPropertySpoofEnabled` still covers `SystemProperties.get()` reads on those devices |

### PairIP license bypass

| Boundary | Detail |
|---|---|
| Coverage | Neutralizes only the license-check client (`com.pairip.licensecheck.LicenseClient.bindToLicensingService(boolean)`) |
| Not covered | PairIP's **vm packing layer** — a separate anti-tamper / anti-debug / anti-Frida framework. With that layer active, the engine cannot start at all: the packing layer monitors Frida's Java bridge and terminates the app the moment any Java API fires during `init()`. See [Troubleshooting](troubleshooting.md) |

### Installed-package spoofing

| Boundary | Detail |
|---|---|
| Coverage | Direct lookups (`getPackageInfo`, `getApplicationInfo`) and enumeration (`getInstalledPackages`, `getInstalledApplications`) |
| Not covered | `queryIntentActivities` / `resolveActivity` augmentation — a fabricated package has no real activities, and constructing a valid `ResolveInfo` / `ActivityInfo` chain with a plausible `ComponentName` is substantially more involved than a `PackageInfo` / `ApplicationInfo` construction. A caller enumerating launchable activities will not observe fabricated entries; direct presence checks will |

### Suspicious-package hiding

| Boundary | Detail |
|---|---|
| Coverage | PackageManager lookups and enumeration, `queryIntentActivities`, `resolveActivity`, and `LauncherApps.getActivityList` |
| Not covered | Native/shell enumeration — a target that spawns `pm list packages` via `Runtime.exec` or `ProcessBuilder` bypasses these hooks entirely. That is a general command-execution concern, not specific to package-list retrieval |

### Hardware-feature spoofing

| Boundary | Detail |
|---|---|
| Coverage | `hasSystemFeature(String)` and `hasSystemFeature(String, int)` |
| Not covered | `getSystemAvailableFeatures()` — constructing well-formed `FeatureInfo` instances (with `glEsVersion`, `reqGlEsVersion`, `flags`) for injection is substantially more involved than a boolean override, and `hasSystemFeature()` is the far more commonly checked entry point |

### VPN / proxy bypass

| Boundary | Detail |
|---|---|
| Coverage | Java-layer reads only — `NetworkInterface`, `NetworkCapabilities`, `NetworkInfo`, `ConnectivityManager`, `LinkProperties`, `android.net.Proxy`, `ProxyInfo`, `java.net.ProxySelector`, `System.getProperty` |
| Not covered | Native socket enumeration; direct `/proc/net` reads; kernel-level routing checks. A target that inspects kernel network state or opens raw sockets bypasses these hooks |

### Device-ID spoofing

| Boundary | Detail |
|---|---|
| Coverage | Java-API surface — `TelephonyManager`, `NetworkInterface`, `WifiInfo`, `BluetoothAdapter`, `AdvertisingIdClient`, `androidx.ads.identifier`, `SubscriptionInfo`, and `ANDROID_ID` via the shared Settings hook |
| Not covered | Native-layer identifier sources — code that reads `/proc/net`, issues raw ioctls, or queries the kernel directly for a MAC address does not go through these methods and is not covered |

### FLAG_SECURE bypass

| Boundary | Detail |
|---|---|
| Coverage | `Window.setFlags` / `addFlags` / `setAttributes`, `SurfaceView.setSecure`, `WindowManagerImpl.addView` / `updateViewLayout` |
| Not covered | Surfaces created directly through the native compositor (e.g. some DRM playback paths) that bypass the `Window` / `SurfaceView` Java API entirely |

### Locale / timezone spoofing — runtime scope

| Boundary | Detail |
|---|---|
| Scope | Process-wide, not per-activity. The JVM-wide default locale is mutated via `Locale.setDefault()`, so every caller in the process observes the spoofed locale — including resource resolution, currency formatting, date/time formatting, and number formatting |
| Side effect | App UI text that has locale-qualified string resources will resolve to the spoofed locale's variant (or fall back to the base variant if no match exists). The app's displayed language, currency symbol, date order, and digit grouping change accordingly |

### RegisterNatives discovery

| Boundary | Detail |
|---|---|
| Coverage | Discovery only — logs native method registrations; does not hook or modify them |
| Not covered | Native methods registered before `init()` completes (very early in process startup) may be missed. The exact window depends on when the gadget loads relative to the app's own JNI registration |
| Symbol resolution | On a build with stripped `libart.so` symbols, the default heuristic finds zero candidates. Supply `registerNativesLogLocator.symbolName` or `.offset` manually — see [Modules](modules.md#registernatives-discovery--logging) |

### Native hooks / native patches

| Boundary | Detail |
|---|---|
| Architecture | Architecture-agnostic at the API level. The engine cannot validate that a `nativePatches` byte sequence is well-formed for the target CPU — a malformed patch can corrupt execution |
| Target resolution | A `symbolName` or `offset` locator is ASLR-safe; `absoluteAddress` is not. On each app launch, `absoluteAddress` values from a prior session will point at unrelated memory |
| Ordering | Both modules install before `sslPinningBypass`. Reordering risks overwriting the SSL module's `Interceptor.attach()` trampoline — see [Architecture](architecture.md) |

### Frida detection

The engine does not include a Frida-detection bypass. It assumes the
gadget has already loaded successfully and is running. Targets that
actively detect Frida — checking for `frida` / `gum` strings in memory
maps, Frida's default port 27042, thread names like `gum-js-loop`, or
`/data/local/tmp/re.frida.server` remnants — may refuse to start or
terminate before any hook takes effect. See
[Troubleshooting](troubleshooting.md).

---

## Related pages

- [Modules](modules.md) — per-module description and mini config
- [Configuration](configuration.md) — full parameter reference and config model
- [Module Pairing](pairing.md) — how modules interact and contribute values
- [Troubleshooting](troubleshooting.md) — common errors and how to resolve them