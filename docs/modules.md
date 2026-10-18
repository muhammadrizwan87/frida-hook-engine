# Modules

21 modules, grouped by function. Every module is off by default. To
enable one, set its flag to `true` in `config.json` (Gadget Script mode)
or edit the source-level default in `engine.js` (CLI attach / spawn).

Each entry lists the module's hook targets, when to enable it, its value
schema (if any), how it relates to other modules, and its coverage
limits.

**A note on pairing.** Every module is independent. No combination is
required. Where two modules are commonly enabled together, that is
stated — but the pairing is a convenience, not a dependency.

---

## TLS / Network

### SSL Pinning Bypass

`sslPinningBypassEnabled` — bypasses TLS certificate pinning in the
Java/Kotlin TLS stack and, for Flutter apps, in BoringSSL's native
verify function.

**Hooks:**

- **Java/Kotlin layer:** `SSLContext`, `TrustManagerFactory`,
  `HttpsURLConnection`, OkHttp `CertificatePinner`, Android Network
  Security Config, TrustKit, Appmattus CT. Plus two runtime-discovery
  passes for obfuscated builds — signature-based reflection over live
  `X509TrustManager` / `HostnameVerifier` instances, and call-stack
  discovery of OkHttp's internal pin-check method anchored on
  `android.net.http.X509TrustManagerExtensions`.
- **Native layer (Flutter):** locates BoringSSL's
  `ssl_crypto_x509_session_verify_cert_chain` in `libflutter.so` via
  string-anchor + ADRP cross-reference + prologue scan. Forces its
  return to `1` on every call.

**Enable when:** intercepting HTTPS traffic via MITM proxy, or
analyzing Flutter apps that use `dart:io` TLS.

**Pairing:** Independent of `vpnProxyBypassEnabled`. The two are often
enabled together during MITM work, but neither depends on the other.
Enable `vpnProxyBypassEnabled` only when the target also refuses to run
under a proxy or VPN.

**Ordering:** The engine installs this module last. Its
`Interceptor.attach()` trampoline on `libflutter.so` must be allocated
after `nativePatches` writes its raw instruction bytes. Do not reorder.

**Limits:** Native layer is ARM64-only. No WebView-in-separate-process
or Cronet coverage. Manually implemented certificate-hash comparisons
without a library are not covered.

```jsonc
"sslPinningBypassEnabled": true
```

### VPN / Proxy Detection Bypass

`vpnProxyBypassEnabled` — hides VPN and proxy state from the standard
Android and JVM detection APIs.

**Hooks:**

- **Network identity:** `NetworkInterface.getName`,
  `NetworkCapabilities.hasTransport` / `hasCapability` /
  `getTransportTypes`, `NetworkInfo.getType` / `getTypeName`,
  `ConnectivityManager.getActiveNetworkInfo`
- **JVM proxy:** `java.net.ProxySelector.getDefault().select(URI)` on
  the concrete runtime class
- **Current Android proxy APIs:**
  `ConnectivityManager.getDefaultProxy` / `getProxyForNetwork(Network)`
  / `getGlobalProxy`, `LinkProperties.getHttpProxy`
- **Legacy Android proxy APIs:** `android.net.Proxy.getHost(Context)` /
  `getPort(Context)` / `getDefaultHost` / `getDefaultPort` /
  `getProxy(Context, String)`
- **ProxyInfo object-level defense-in-depth:** `getHost` / `getPort` /
  `getPacFileUrl` / `getSocketAddress` / `makeProxy` / `toString` /
  `isPacProxy` / `isValid`
- **JVM properties:** `System.getProperty` (both overloads) for
  VPN/proxy keys

**Enable when:** the target refuses to run under a VPN or proxy, or a
MITM-proxy detection needs suppression.

**Pairing:** Independent of `sslPinningBypassEnabled`. Enable only when
the target requires it.

**Limits:** No native socket enumeration or `/proc/net` reads.

```jsonc
"vpnProxyBypassEnabled": true
```

---

## Tamper Surfaces

### Installer-Source Spoofing

`installerSpoofEnabled` — reports `com.android.vending` (Play Store) as
the app's installer.

**Hooks:** `PackageManager.getInstallerPackageName(String)`,
`InstallSourceInfo.getInstallingPackageName()`,
`getInitiatingPackageName()`, `getOriginatingPackageName()`. All three
`InstallSourceInfo` getters are hooked together so a caller
cross-checking installing / initiating / originating package names does
not observe an inconsistency.

**Enable when:** the target checks installer source to detect
sideloading.

**Pairing:** Independent of every other module. Often useful alongside
`pairipLicenseBypassEnabled` on Play-Store-distributed apps, but neither
requires the other.

```jsonc
"installerSpoofEnabled": true
```

### Suspicious-Package Hiding (Blocklist)

`suspiciousPackageSpoofEnabled` — hides listed packages from the
target app's PackageManager queries.

**Hooks:**

- `PackageManager.getPackageInfo(String, int)` and the API 33+
  `PackageInfoFlags` overload
- `PackageManager.getApplicationInfo(String, int)` and the API 33+
  `ApplicationInfoFlags` overload
- `PackageManager.getInstalledPackages(int)` / `(long, int)` /
  `(PackageInfoFlags)`
- `PackageManager.getInstalledApplications(int)` / `(long, int)` /
  `(ApplicationInfoFlags)`
- `PackageManager.queryIntentActivities(Intent, int)` and the API 33+
  `ResolveInfoFlags` overload
- `PackageManager.resolveActivity(Intent, int)` and the API 33+
  `ResolveInfoFlags` overload
- `LauncherApps.getActivityList(String, UserHandle)`

Direct lookups throw `NameNotFoundException`. Enumeration results are
rebuilt as a fresh `ArrayList` with the configured packages removed;
`ParceledListSlice` wrapping is preserved when present.

**Value schema:** `suspiciousPackagesCustom` — open string array. An
empty list hides nothing, by design.

**Enable when:** hiding root managers, Xposed/LSPosed, patchers,
emulator packages, or anything else from the target's detection.

**Pairing:** Independent of `installedPackageSpoofEnabled`. The two
modules are inverses — this one removes packages from the target's
view; `installedPackageSpoofEnabled` adds them. They can be used
together, but a package listed in both is a configuration mistake.

**Limits:** Native/shell enumeration (`pm list packages` spawned via
`Runtime.exec`) is not covered.

```jsonc
"suspiciousPackageSpoofEnabled": true,
"suspiciousPackagesCustom": [
  "com.topjohnwu.magisk",
  "me.weishu.kernelsu",
  "org.lsposed.manager",
  "de.robv.android.xposed.installer",
  "eu.chainfire.supersu",
  "bin.mt.plus",
  "com.termux"
]
```

### Installed-Package Spoofing (Whitelist)

`installedPackageSpoofEnabled` — makes configured packages appear
installed even though they are not actually present on the device.

**Hooks:** the same entry points as the blocklist module, inverted.
Fabricated `PackageInfo` / `ApplicationInfo` objects are appended to
enumeration results and returned from direct lookups.

**Fabricated entries carry:** `packageName`, `versionName`,
`versionCode` / `longVersionCode`, `firstInstallTime`, `lastUpdateTime`,
`applicationInfo` with a plausible `sourceDir` / `publicSourceDir` /
`dataDir` / `nativeLibraryDir`, a `uid` in the user-app range
(10000+), and the `FLAG_INSTALLED` bit. `FLAG_SYSTEM` is set only if the
per-package config declares `isSystem: "true"`.

**Value schema:** `installedPackageSpoofValues` — nested map keyed by
package name. All inner fields are optional strings; the module supplies
defaults (`versionName` `"1.0.0"`, `versionCode` `"1"`, `uid` `"10123"`,
`isSystem` `"false"`). An empty inner object `{}` is valid — all
defaults apply.

**Enable when:** the target requires Play Store, GMS, or another
specific package to be present.

**Pairing:** Independent of `pairipLicenseBypassEnabled`. On devices
without Play Store, both modules are commonly needed to make a
PairIP-Licensed app runnable — but the dependency is on the device
environment, not between the modules. On a device that already has Play
Store installed, this module is unnecessary.

**Limits:** `queryIntentActivities` / `resolveActivity` are not
augmented — a fabricated package has no real activities.

```jsonc
"installedPackageSpoofEnabled": true,
"installedPackageSpoofValues": {
  "com.android.vending": {
    "versionName": "53.3.21-34 [0] [PR] 986224237",
    "versionCode": "85332140",
    "uid": "10159",
    "isSystem": "true"
  },
  "com.google.android.gms": {
    "versionName": "26.34.36 (260400-981326859)",
    "versionCode": "263436035",
    "uid": "14134",
    "isSystem": "true"
  },
  "com.google.android.gsf": {
    "versionName": "14134",
    "versionCode": "36",
    "uid": "14134",
    "isSystem": "true"
  }
}
```

### ADB / Developer Options Bypass

`adbDevSettingsBypassEnabled` — reports Developer Options and ADB as
disabled.

**Hooks:** `Settings.Secure` / `Settings.Global` / `Settings.System`
`getInt` (2-arg and 3-arg) and `getString` for
`development_settings_enabled` → `"0"` and `adb_enabled` → `"0"`.

**Enable when:** the target refuses to run with Developer Options or
ADB enabled.

**Pairing:** Independent of every other module. For complete coverage of
apps that read Settings via `ContentResolver` directly (bypassing the
convenience `Settings.Secure` / `Settings.Global` methods), also enable
`contentProviderSpoofEnabled` — it will merge the same keys into its
`settings` authority automatically.

```jsonc
"adbDevSettingsBypassEnabled": true
```

### Mock-Location Bypass

`mockLocationBypassEnabled` — hides mock-location usage from
per-`Location` checks and system-wide app-op checks.

**Hooks:**

- `Location.isFromMockProvider()` → `false`
- `Location.isMock()` → `false`
- `AppOpsManager.checkOp` / `checkOpNoThrow` / `unsafeCheckOp` /
  `unsafeCheckOpNoThrow` for `OPSTR_MOCK_LOCATION`
  (`"android:mock_location"`) → `MODE_IGNORED`, across both the 3-arg
  `(String, int, String)` and the 4-arg
  `(String, int, String, String)` overloads

**Enable when:** GPS-spoofing scenarios, fake-GPS app testing, or a
target that treats mock location as a tamper signal.

**Pairing:** Independent of every other module. For complete coverage of
apps that read the legacy `Settings.Secure` `"mock_location"` key (or
query `content://settings/...` directly), also enable
`contentProviderSpoofEnabled` — it will merge the same key into its
`settings` authority automatically.

```jsonc
"mockLocationBypassEnabled": true
```

### Auto-Time / Auto-Timezone Spoofing

`autoTimeSpoofEnabled` — forces automatic clock and timezone mode.

**Hooks:** `Settings.Secure` / `Settings.Global` / `Settings.System`
`getInt` / `getString` for `"auto_time"` → `"1"` and
`"auto_time_zone"` → `"1"`.

**Enable when:** the target treats manually-managed time as a tamper
signal.

**Pairing:** Independent of every other module. Also merged into
`contentProviderSpoofEnabled`'s `settings` authority automatically when
that module is enabled.

```jsonc
"autoTimeSpoofEnabled": true
```

---

## License / Anti-Tamper

### PairIP License Bypass
> NOTE: not a paid/commercial license bypass. This only unblocks a   
> free app's client-side PairIP check inside a virtualized/emulated   
> research environment.

`pairipLicenseBypassEnabled` — neutralizes Google Play's PairIP
license-check client.

**Hooks:**
`com.pairip.licensecheck.LicenseClient.bindToLicensingService(boolean)`
→ empty implementation. The original method is never called and no
return value is produced (the method's declared return type is void).

**Enable when:** the target app ships with Google Play's PairIP license.

**Pairing:** Independent of `installedPackageSpoofEnabled` and
`installerSpoofEnabled`. PairIP's own runtime check may verify Play
Store presence or installer source through a separate code path — on a
device without Play Store, both `installedPackageSpoofEnabled` and this
module are commonly required to make the app runnable. On a device that
already has Play Store, `installedPackageSpoofEnabled` is unnecessary.
`installerSpoofEnabled` is orthogonal — enable it only if the target's
own code (not PairIP) checks installer source.

**Limits:** This module neutralizes only the license-check client. If
the target is packed with PairIP's **vm packing layer** (a separate,
heavier anti-tamper / anti-debug / anti-Frida framework), the engine
cannot run at all — see [Troubleshooting](troubleshooting.md).

```jsonc
"pairipLicenseBypassEnabled": true,
"installedPackageSpoofEnabled": true,
"installedPackageSpoofValues": {
  "com.android.vending": { "isSystem": "true" },
  "com.google.android.gms": { "isSystem": "true" },
  "com.google.android.gsf": { "isSystem": "true" }
}
```

*(The `installedPackageSpoofEnabled` half is only required when the
device does not already have Play Store / GMS / GSF installed.)*

---

## UI / Display

### FLAG_SECURE Bypass

`flagSecureBypassEnabled` — allows screenshots and screen recording of
surfaces that set `FLAG_SECURE`.

**Hooks:** `Window.setFlags`, `Window.addFlags`,
`Window.setAttributes`, `SurfaceView.setSecure`,
`WindowManagerImpl.addView`, `WindowManagerImpl.updateViewLayout`.
`FLAG_SECURE` (`0x2000`) is stripped from every path.

**Enable when:** screenshotting or screen-recording a target app that
sets `FLAG_SECURE`.

**Limits:** Only the `Window` / `SurfaceView` APIs. A surface created
directly through the native compositor (e.g. some DRM playback paths)
is not covered.

```jsonc
"flagSecureBypassEnabled": true
```

---

## Device Identity

### Build-Prop Spoofing

`buildPropSpoofEnabled` — mutates `android.os.Build` fields to a
configurable device profile.

**Mechanism:** direct field mutation, not method hooking. Every reader —
including internal framework code — observes the spoofed values, since
there is a single underlying field slot.

**Fields covered:** `MANUFACTURER`, `MODEL`, `BRAND`, `PRODUCT`,
`DEVICE`, `HARDWARE`, `BOARD`, `BOOTLOADER`, `HOST`, `ID`,
`FINGERPRINT`, `TAGS`, `TYPE`, `USER`, `DISPLAY`, and (on
`android.os.Build$VERSION`) `RELEASE`, `SECURITY_PATCH`, `INCREMENTAL`,
`CODENAME`. Also `Build.getSerial()` and `Build.getRadioVersion()`.

**Deliberately excluded:** `SDK_INT` (commonly gates the app's own code
paths) and the ABI lists (spoofing them risks crashing the app if it
subsequently loads a native library for an architecture the device does
not actually have).

**Value schema:** `buildPropSpoofValues` — closed-key flat map. Only the
declared keys are accepted.

**Enable when:** emulator detection bypass, cross-device testing.

**Pairing:** Independent of `systemPropertySpoofEnabled`. Both are
commonly enabled together for emulator detection bypass, but neither
depends on the other. `Build` fields are populated from `SystemProperties`
only once, at class-initialization time — the two modules are
complementary, not redundant.

**Limits:** Android 17 (API 37+) restricts reflective writes to
`public static final` fields. Writes may fail per-field on affected
devices; the rest of the engine continues.

```jsonc
"buildPropSpoofEnabled": true,
"buildPropSpoofValues": {
  "manufacturer": "Google",
  "model": "Pixel 7 Pro",
  "brand": "google",
  "product": "cheetah",
  "device": "cheetah",
  "hardware": "cheetah",
  "board": "cheetah",
  "bootloader": "unknown",
  "host": "android-build",
  "id": "AP4A.241205.013",
  "fingerprint": "google/cheetah/cheetah:15/AP4A.241205.013/12621605:user/release-keys",
  "tags": "release-keys",
  "type": "user",
  "user": "android-build",
  "display": "AP4A.241205.013",
  "release": "15",
  "securityPatch": "2024-12-05",
  "incremental": "12621605",
  "codename": "REL"
}
```

### System-Property Spoofing

`systemPropertySpoofEnabled` — hooks `android.os.SystemProperties.get()`
for raw property reads.

**Hooks:** `SystemProperties.get(String)` and `get(String, String)` —
the hidden-API methods every raw `ro.*` / `persist.*` / `qemu.*`
property read goes through.

**Value schema:** `systemPropertySpoofValues` — open-key flat map. Any
property name is accepted.

**Enable when:** emulator or root detection bypass, bootloader-status
checks, or any target that reads properties directly instead of going
through `android.os.Build`.

**Pairing:** Independent of `buildPropSpoofEnabled`. The two cover
different reads — `buildPropSpoofEnabled` mutates the already-initialized
`Build.*` fields; this module covers every other `SystemProperties.get()`
caller. Enable either or both, depending on the target.

```jsonc
"systemPropertySpoofEnabled": true,
"systemPropertySpoofValues": {
  "ro.boot.verifiedbootstate": "green",
  "ro.boot.vbmeta.device_state": "locked",
  "ro.boot.veritymode": "enforcing",
  "ro.boot.flash.locked": "1",
  "ro.oem_unlock_supported": "0",
  "ro.secureboot.lockstate": "locked",
  "ro.kernel.qemu": "0",
  "ro.boot.qemu": "0",
  "ro.secure": "1",
  "ro.debuggable": "0",
  "ro.force.debuggable": "0",
  "ro.adb.secure": "0",
  "ro.allow.mock.location": "0",
  "qemu.hw.mainkeys": "1"
}
```

### Device-ID Spoofing

`deviceIdSpoofEnabled` — spoofs IMEI, MEID, ICCID, IMSI, phone number,
Wi-Fi / Bluetooth MAC, advertising ID, and internal IP.

**Hooks:**

- `TelephonyManager.getDeviceId` / `getImei` / `getMeid` (both the
  0-arg and 1-arg overloads), `getSimSerialNumber`, `getSubscriberId`,
  `getLine1Number`
- `NetworkInterface.getHardwareAddress`
- `WifiInfo.getMacAddress` and `WifiInfo.getIpAddress`
- `BluetoothAdapter.getAddress`
- `com.google.android.gms.ads.identifier.AdvertisingIdClient$Info.getId`
  and `isLimitAdTrackingEnabled`
- `androidx.ads.identifier.AdvertisingIdInfo.getId` and
  `isLimitAdTrackingEnabled`
- `SubscriptionInfo.getIccId` and `getNumber`

**Value schema:** Two modes, selected by `deviceIdSpoofUseRandom`.

| Mode | Selected when | Source |
|---|---|---|
| **Fixed profile** | `deviceIdSpoofUseRandom: false` (default) | `deviceIdSpoofValues` — closed-key flat map |
| **Random** | `deviceIdSpoofUseRandom: true` | Fresh values generated once per `init()` |

**Random mode ignores `deviceIdSpoofValues` entirely.** With
`deviceIdSpoofUseRandom: true`, values are computed fresh at each app
launch. The same generated set is used consistently within that launch,
so `TelephonyManager` reads, network reads, and the `android_id`
delivered via the shared Settings hook all report matching values.

Generated values in random mode:

- **IMEI** — 14 random digits + a valid Luhn check digit (15 total).
- **MEID** — 14 random hex characters.
- **ICCID** — `89` prefix + 16 random digits + Luhn check digit (19 total).
- **IMSI** — MCC+MNC derived from the effective `geoSpoofValues.plmn`
  (falls back to a valid default if the configured PLMN is malformed),
  padded with random digits to 15 total. This keeps a randomly-generated
  IMSI consistent with whatever carrier identity
  `geoRestrictionBypassEnabled` is also spoofing.
- **Wi-Fi / Bluetooth MAC** — drawn from a small pool of real,
  publicly-known consumer-device OUI prefixes (rather than a
  fully-random first octet, since the locally-administered bit pattern
  `02:xx:xx` or the classic QEMU / VirtualBox prefixes are themselves
  emulator signatures).
- **Advertising ID** — RFC 4122 version-4 UUID.
- **Internal IP** — `192.168.x.y` (consumer-router range). Deliberately
  avoids `10.0.2.x` and `10.0.0.x`, which are classic AVD emulator
  addresses.

**ANDROID_ID** is delivered separately via the shared Settings hook — not
a `TelephonyManager` read. In both modes, the effective value is combined
with `adbDevSettingsBypassEnabled`, `mockLocationBypassEnabled`, and
`autoTimeSpoofEnabled` into a single Settings installation.

**Enable when:** emulator detection bypass, or a per-install identifier
reset (use random mode for a fresh set on each launch).

**Pairing:** Independent of every other module. Its `android_id`
contribution flows into `contentProviderSpoofEnabled`'s `settings`
authority automatically when that module is enabled.

**Limits:** Java-API surface only. Native-layer identifier sources
(e.g. code that reads `/proc/net` or issues raw ioctls) are not covered.

**Mini config — fixed profile:**

```jsonc
"deviceIdSpoofEnabled": true,
"deviceIdSpoofUseRandom": false,
"deviceIdSpoofValues": {
  "androidId": "a1b2c3d4e5f6a7b8",
  "imei": "356938035643809",
  "meid": "A1000012B3C456",
  "iccid": "89014103211118510720",
  "imsi": "310260123456789",
  "phoneNumber": "+15555215556",
  "wifiMac": "3C:5A:B4:1E:2F:8D",
  "bluetoothMac": "AC:37:43:2B:9C:14",
  "advertisingId": "38400000-8cf0-11bd-b23e-10b96e40000d",
  "internalIp": "192.168.1.42"
}
```

**Mini config — random:**

```jsonc
"deviceIdSpoofEnabled": true,
"deviceIdSpoofUseRandom": true
```

Random mode ignores `deviceIdSpoofValues`, so the value object does not
need to be listed at all.

---

## Environment

### Geo / Carrier Identity Spoofing

`geoRestrictionBypassEnabled` — spoofs carrier name, PLMN, and
network/SIM country.

**Hooks:**

- `TelephonyManager.getNetworkOperatorName` /
  `getSimOperatorName` / `getSimCarrierIdName` → operator name
- `TelephonyManager.getNetworkOperator` / `getSimOperator` → PLMN
- `TelephonyManager.getNetworkCountryIso` / `getSimCountryIso` →
  country ISO
- `SubscriptionInfo.getCountryIso` / `getCarrierName` / `getMcc` /
  `getMnc` / `getMccString` / `getMncString` — derived from the same
  values (`plmn` is split into MCC+MNC)

**Value schema:** `geoSpoofValues` — closed-key flat map.

| Key | Default | Notes |
|---|---|---|
| `operatorName` | `"AT&T"` | Carrier display name |
| `plmn` | `"310410"` | MCC+MNC, exactly 5 or 6 digits. Malformed lengths fall back to a built-in default for MCC/MNC-derived getters |
| `countryIso` | `"us"` | ISO-3166-1 alpha-2, lowercase |

**Enable when:** geo-restricted content availability, or
carrier-specific feature gating.

**Pairing:** Independent of `localeSpoofEnabled`. This module spoofs
carrier and network identity; `localeSpoofEnabled` spoofs displayed
language, region, and formatting. Enable either or both, depending on
what the target reads.

```jsonc
"geoRestrictionBypassEnabled": true,
"geoSpoofValues": {
  "operatorName": "T-Mobile",
  "plmn": "310260",
  "countryIso": "us"
}
```

### Locale / Timezone Spoofing

`localeSpoofEnabled` — spoofs language, country, and timezone.

**Hooks:**

- `Locale.getCountry()` and `Locale.getLanguage()`
- `Locale.setDefault(Locale)` and
  `Locale.setDefault(Category, Locale)` — mutates the JVM-wide default
  for both the DISPLAY and FORMAT categories
- `TimeZone.getID()`
- `Configuration.getLocales()` and `LocaleList.getDefault()` — each
  returns a fresh `LocaleList` on every call

**Value schema:** `localeSpoofValues` — closed-key flat map.

| Key | Default | Notes |
|---|---|---|
| `country` | `"US"` | ISO-3166-1 alpha-2, uppercase |
| `language` | `"en"` | ISO-639-1, lowercase |
| `timezoneId` | `"America/New_York"` | IANA zone ID |

**Enable when:** language- or region-gated UI, or testing
locale-dependent formatting.

**Runtime impact.** This module is broader than "displayed language". It
changes the JVM-wide default locale, which Android's resource-resolution
machinery reads for:

- **App language** — any string resource with a locale-qualified variant
  resolves to the spoofed locale's variant (or falls back to the base
  variant if no match exists).
- **Currency symbol and formatting** — `NumberFormat.getCurrencyInstance()`
  and `DecimalFormat` with a currency pattern use the spoofed locale's
  currency symbol and decimal/grouping separators.
- **Date and time formatting** — `DateFormat` and `SimpleDateFormat`
  use the spoofed locale's month names, weekday names, and date order.
- **Number formatting** — decimal separator, thousands separator, and
  digit grouping follow the spoofed locale.
- **Timezone** — `TimeZone.getDefault()` and any code reading
  `TimeZone.getID()` observes the spoofed zone.

These effects apply process-wide, not only to a specific activity. If
the target app has locale-specific UI, its appearance will change
accordingly.

**Pairing:** Independent of `geoRestrictionBypassEnabled`. Enable this
module only when locale-dependent behavior needs to be spoofed, and
`geoRestrictionBypassEnabled` only when carrier / network identity does.
They are often enabled together for region-locked content, but neither
requires the other.

```jsonc
"localeSpoofEnabled": true,
"localeSpoofValues": {
  "country": "US",
  "language": "en",
  "timezoneId": "America/New_York"
}
```

### Hardware-Feature Spoofing

`hardwareFeatureSpoofEnabled` — forces `PackageManager.hasSystemFeature()`
to report listed features as present regardless of actual hardware.

**Hooks:** `PackageManager.hasSystemFeature(String)` and
`hasSystemFeature(String, int)`.

**Value schema:** `spoofedHardwareFeatures` — open string array. Any
valid feature string is accepted.

**Enable when:** emulator detection bypass. Emulators commonly lack real
telephony, camera, or sensor hardware, and feature checks against those
specific strings are a common detection signal.

**Limits:** `getSystemAvailableFeatures()` (returning the full
`FeatureInfo[]` array) is not covered. Constructing well-formed
`FeatureInfo` objects for injection is substantially more involved than
a boolean override; `hasSystemFeature()` is the far more commonly
checked entry point.

```jsonc
"hardwareFeatureSpoofEnabled": true,
"spoofedHardwareFeatures": [
  "android.hardware.telephony",
  "android.hardware.camera",
  "android.hardware.camera.any",
  "android.hardware.camera.front",
  "android.hardware.sensor.accelerometer",
  "android.hardware.sensor.gyroscope",
  "android.hardware.sensor.proximity",
  "android.hardware.bluetooth",
  "android.hardware.nfc",
  "android.hardware.fingerprint",
  "android.hardware.wifi"
]
```

---

## Content Providers

### ContentProvider Spoofing

`contentProviderSpoofEnabled` — intercepts direct ContentProvider reads
that bypass the convenience Settings and TelephonyManager APIs.

**Hooks:**

- `ContentResolver.call(String authority, String method, String arg, Bundle extras)`
- `ContentResolver.call(Uri uri, String method, String arg, Bundle extras)`
- `ContentResolver.query(Uri, String[], String, String[], String)`
- `ContentProviderClient.query(Uri, String[], String, String[], String)`

**Value schema:** `contentProviderSpoofValues` — nested map keyed by
authority. Both the authority set and the keys within each authority are
open-ended.

**Special handling — `settings` authority:**

- `call()` is intercepted only for `GET_secure` / `GET_global` /
  `GET_system` method names. `PUT_*` calls pass through unchanged, so a
  caller that writes a setting still writes it.
- `query()` and `ContentProviderClient.query()` are best-effort — the
  module extracts every plausible key from the URI path segment,
  `name='<key>'` literals, and `name=?` parameters, and returns a
  synthesized `MatrixCursor` if it can match a key. A projection the
  module cannot handle falls through to the real query rather than
  crashing the host app.

**Automatic value contributions.** The `settings` authority's map is
merged at apply time with keys derived from other enabled flags:

| Contributor flag | Adds key(s) |
|---|---|
| `adbDevSettingsBypassEnabled` | `development_settings_enabled`, `adb_enabled` |
| `mockLocationBypassEnabled` | `mock_location` |
| `autoTimeSpoofEnabled` | `auto_time`, `auto_time_zone` |
| `deviceIdSpoofEnabled` | `android_id` |

You do not need to list those keys twice — the higher-level flags win on
overlap.

**Enable when:** the target reads `content://settings/...` or
`content://com.google.android.gsf.gservices` directly, or queries the
underlying ContentProvider rather than going through the convenience
`Settings.Secure` / `Settings.Global` methods.

**Pairing:** Independent of `adbDevSettingsBypassEnabled`,
`mockLocationBypassEnabled`, `autoTimeSpoofEnabled`, and
`deviceIdSpoofEnabled`. Enable `contentProviderSpoofEnabled` in addition
to any of those when the target uses `ContentResolver` directly — the
module will pick up their keys automatically.

```jsonc
"contentProviderSpoofEnabled": true,
"contentProviderSpoofValues": {
  "settings": {
    "development_settings_enabled": "0",
    "adb_enabled": "0",
    "mock_location": "0",
    "android_id": "a1b2c3d4e5f6a7b8"
  },
  "com.google.android.gsf.gservices": {
    "android_id": "3f9d0a2b4c5e6f71"
  }
}
```

---

## Config-Driven Hooks

### Config-Driven Java Hooking

`javaHooksEnabled` — enables the config-driven Java / Kotlin method
hooking module. The hook definitions themselves are supplied via the
companion `javaHooks` array; nothing is hooked while `javaHooksEnabled`
is `false`.

**Hooks:** arbitrary methods, defined at runtime via `javaHooks`.

**Schema (per entry):**

| Field | Required | Notes |
|---|---|---|
| `className` | yes | Fully qualified with dots |
| `methodName` | yes | Exact name |
| `argTypes` | recommended | Selects a specific overload. Java source form for primitives (`"boolean"`, `"int"`); JNI form for arrays (`"[B"`, `"[Ljava.lang.String;"`). Omit only for single-overload methods — omitting against a multi-overload method hooks all of them with one implementation and one declared `returnType`, which the engine warns about |
| `returnType` | no | Used only to coerce `forceReturn` and to detect void — not for overload resolution |
| `onCall` | no | Behavior block; absent = observe only |

**`onCall` sub-keys:**

| Key | Behavior |
|---|---|
| `logArgs` | Log every argument with its declared type |
| `logReturn` | Log the original return (no effect on void) |
| `modifyArgs` | `{ "<0-based idx>": <value> }` — args coerced via `argTypes[idx]` |
| `nop` | Skip the original implementation |
| `forceReturn` | Override the return (applied after the original unless `nop` is also set) |

**Pairing rules:**

- `nop` + non-void + no `forceReturn` returns `undefined` at the JNI
  boundary — supply `forceReturn` instead.
- `modifyArgs` without `nop` — the original still runs and sees the
  modified args.
- `forceReturn` without `nop` — the original runs (side effects happen);
  only the return value is overridden.
  
**Coercion.** `forceReturn` and `modifyArgs` values are coerced through
the declared `argTypes[idx]` / `returnType`. Primitives map to plain JS
values (Frida marshals them at the JNI boundary). Boxed wrapper types
(`java.lang.Boolean`, `Integer`, `Long`, `Float`, `Double`, `Short`,
`Byte`, `Character`) are boxed explicitly — this matters for Kotlin,
where nullable primitives (`Boolean?`, `Int?`) compile to wrapper
types. See [Advanced Usage → Coercion rules](advanced-usage.md#coercion-rules-for-forcereturn-and-modifyargs)
for the full table.

**Installation:** deferred, non-blocking. When `javaHooksEnabled` is
`true`, these hooks target the app's own classes, which may not be
loaded yet when `init()` runs. Each entry retries up to 10 times at
500 ms. App startup is not delayed.

```jsonc
"javaHooksEnabled": true,
"javaHooks": [
  {
    "className": "com.example.Logger",
    "methodName": "writeLog",
    "argTypes": ["java.lang.String"],
    "returnType": "void",
    "onCall": { "logArgs": true, "nop": true }
  },
  {
    "className": "com.example.RootChecker",
    "methodName": "isDeviceRooted",
    "returnType": "boolean",
    "onCall": { "logReturn": true, "nop": true, "forceReturn": false }
  },
  {
    "className": "com.example.LicenseManager",
    "methodName": "isValidLicense",
    "argTypes": ["java.lang.String", "int"],
    "returnType": "boolean",
    "onCall": {
      "logArgs": true,
      "logReturn": true,
      "modifyArgs": { "1": 9999 },
      "forceReturn": true
    }
  }
]
```

### Native (.so) Hooking

`nativeHooksEnabled` — hook native functions in loaded shared libraries.

**Two modes, selected per entry:**

| Mode | Selected when | Behavior |
|---|---|---|
| **Typed** | Both `argTypes` and `returnType` present | Full type safety. Chains to the original via `NativeFunction`. Supports `onCall.nop`. |
| **Raw** | Otherwise | Pointer-sized args and return only. `onCall.nop` is ignored with a warning. |

**Schema (per entry):**

| Field | Required | Notes |
|---|---|---|
| `moduleName` | yes | Must already be loaded when the hook is installed |
| Locator | yes — exactly one | `symbolName` (exported symbol, ASLR-safe), `offset` (hex string from module base, ASLR-safe), or `absoluteAddress` (raw pointer, NOT ASLR-safe — testing only) |
| `argTypes` | typed mode | Array of Frida native type strings |
| `returnType` | typed mode | Single Frida native type string |
| `onCall` | no | Same sub-keys as `javaHooks` |
| `rawArgCount` | no | Raw mode only. How many pointer-sized arg slots `onCall.logArgs` logs. Default `4`. |

**Native type strings:** `void`, `bool`, `int8`, `uint8`, `int16`,
`uint16`, `int32`, `uint32`, `int64`, `uint64`, `int`, `uint`, `char`,
`uchar`, `float`, `double`, `pointer`. `int64` / `uint64` values beyond
`2^53` should be supplied as strings.

**Ordering:** installed before `sslPinningBypass`. The SSL module's
native `Interceptor.attach()` trampoline must not be overwritten by a
later patch. See [Architecture](architecture.md).

```jsonc
"nativeHooksEnabled": true,
"nativeHooks": [
  {
    "moduleName": "libc.so",
    "symbolName": "srand",
    "argTypes": [],
    "returnType": "void",
    "onCall": { "logArgs": true }
  },
  {
    "moduleName": "libtarget.so",
    "offset": "0x1234",
    "argTypes": ["int"],
    "returnType": "int",
    "onCall": { "logArgs": true, "forceReturn": 1 }
  },
  {
    "moduleName": "libc.so",
    "symbolName": "malloc",
    "onCall": { "logArgs": true, "logReturn": true }
  }
]
```

### Native Instruction Patching

`nativePatchesEnabled` — patch raw instruction bytes at a specific
address. This is not a function hook — it directly modifies code bytes
at the target address.

**Schema (per entry):**

| Field | Required | Notes |
|---|---|---|
| `moduleName` | yes | Same rule as `nativeHooks` |
| Locator | yes — exactly one | Same rules as `nativeHooks` |
| `patchBytes` | yes | Array of 2-char hex strings, or a single concatenated hex string |

**String form** must be non-empty and even-length. A malformed string is
rejected before any memory is written — no partial patch is ever
applied. Original bytes are captured before patching and restored
verbatim on `dispose()`.

**Common ARM64 idioms:**

| Purpose | Bytes |
|---|---|
| `NOP` | `1F 20 03 D5` |
| `RET` | `C0 03 5F D6` |
| `MOV W0, #0 ; RET` | `00 00 80 D2  C0 03 5F D6` |
| `MOV W0, #1 ; RET` | `20 00 80 52  C0 03 5F D6` |

**Caveat.** The engine cannot validate that the bytes are well-formed
for the target CPU architecture. A malformed patch can corrupt execution
in ways ranging from a crash to silent incorrect behavior elsewhere in
the process.

**Ordering:** installed before `sslPinningBypass`. See
[Architecture](architecture.md).

```jsonc
"nativePatchesEnabled": true,
"nativePatches": [
  {
    "moduleName": "libtarget.so",
    "offset": "0x2A10",
    "patchBytes": ["1F", "20", "03", "D5"]
  },
  {
    "moduleName": "libtarget.so",
    "offset": "0x5678",
    "patchBytes": "20008052C0035FD6"
  }
]
```

### RegisterNatives Discovery / Logging
> CREDIT: Module concept and implementation contributed   
by Marc Nin (@mragonias).

`registerNativesLogEnabled` — logs every native method registration at
runtime — the declaring class, method name, JNI signature, and the
native function pointer's owning module + offset.

**Hooks:** `JNIEnv::RegisterNatives` inside `libart.so` — the single,
class-independent, fixed ART entry point every native method
registration funnels through.

**Value schema:**

| Parameter | Type | Notes |
|---|---|---|
| `registerNativesLogClassFilter` | array\<string\> | Class names to restrict logging to. Empty (default) logs every call process-wide |
| `registerNativesLogLocator` | object | Optional manual locator: `{ symbolName: "", offset: "" }`. Both empty means "use the heuristic" |

**Target resolution:**

1. If `registerNativesLogLocator.symbolName` is set, use it.
2. Else if `registerNativesLogLocator.offset` is set, use it.
3. Else scan `libart.so`'s exported symbols for names matching `art` +
   `JNI` + `RegisterNatives`, excluding `CheckJNI`. If the scan finds
   multiple candidates, only the first is hooked by default; every
   candidate is logged so a specific one can be pinned via `symbolName`.

**Enable when:** discovering `moduleName` + `offset` targets for
`nativeHooks` / `nativePatches` when the target library is stripped
(common under packers / anti-tamper protections), or when the app
registers natives explicitly via `RegisterNatives()` rather than relying
on the `Java_pkg_Class_method` JNI naming convention.

**Pairing:** Complementary to `nativeHooksEnabled` / `nativePatchesEnabled`.
This module *discovers* the targets those two consume. Point them at
whatever this logs.

**Limits:** Discovery only — no hooking or modifying of native
registrations. Native methods registered before `init()` completes may
be missed.

```jsonc
"registerNativesLogEnabled": true,
"registerNativesLogClassFilter": [
  "com.example.app.NativeBridge",
  "com.example.app.Codec"
]
```

---

## Related pages

- [Configuration](configuration.md) — full parameter reference and config model
- [Module Pairing](pairing.md) — how modules interact and contribute values
- [Module Limits](limits.md) — open vs. closed value maps and platform boundaries
- [Advanced Usage](advanced-usage.md) — custom Java hooks, native hooks, native patches