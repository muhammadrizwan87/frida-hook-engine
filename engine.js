/**
 * frida-hook-engine.js
 *
 * Author / Project:
 *   Author:     MuhammadRizwan from India
 *   Repository: https://github.com/muhammadrizwan87/frida-hook-engine
 *   License:    Apache-2.0
 *   Issues:     https://github.com/muhammadrizwan87/frida-hook-engine/issues
 *
 * Companion projects:
 *   keysigner    https://github.com/muhammadrizwan87/keysigner
 *                APK signing tool
 *   frida-bridge https://github.com/muhammadrizwan87/frida-bridge
 *                Native loader for container / virtual-space environments
 *
 * Built on Frida (https://frida.re) by Ole André Vadla Ravnås and
 * contributors.
 *
 * Purpose:
 *   A configuration-driven Android instrumentation engine for Frida.
 *   Supports three deployment modes from a single codebase:
 *
 *     - Gadget, Script interaction mode. Loaded via
 *       libfrida-gadget.config.so; hook definitions and feature toggles
 *       are externalized to that config, so no recompilation is needed
 *       when targets or behaviors change. This is the primary mode.
 *
 *     - Frida CLI, attach / spawn. Loaded directly with
 *       `frida -U -f <pkg> -l this-file.js`. No config file exists in
 *       this mode, so every toggle uses its source-level default
 *       declared in this file.
 *
 *     - Gadget, Listen mode. Pre-built agent driven from a live Frida
 *       REPL controller. Parameters may be supplied via
 *       rpc.exports.init(); absent keys fall back to source defaults.
 *
 * Return-type coverage:
 *   void; primitives (boolean, byte, short, int, long, float, double);
 *   java.lang.String; object types and arrays (passthrough).
 *
 * Configuration-flag pattern:
 *   Every toggle exposed via parameters is declared as a module-level
 *   variable with a source-level default, annotated with the parameter
 *   key that overrides it at init(). This lets the same defaults apply
 *   in every deployment mode — under Gadget Script mode they are a
 *   baseline that the config overrides per-key; under CLI attach and
 *   Listen mode (or any invocation without Gadget-supplied parameters)
 *   they are the effective values directly. Editing a literal default
 *   in this file and reloading is therefore sufficient to change a
 *   behavior without any config edit.
 */

'use strict';

// This file ships in two forms:
//   - As-is (this file): plain script, no import. Load directly via
//     Frida CLI (`frida -U -f <pkg> -l engine.js`) or Gadget Listen
//     mode. `Java` is provided as a runtime global in both cases.
//   - As a compiled agent (agent.js, shipped alongside): produced by
//     uncommenting the import below, running frida-compile, then
//     re-commenting. End users never perform this step — they use the
//     pre-built agent.js with Gadget's Script interaction mode.

// Uncomment ONLY during your own release build:
// import Java from 'frida-java-bridge';



// ════════════════════════════════════════════════
//                      C O N F I G U R A T I O N                       
// ════════════════════════════════════════════════



// ------------------------------------------------------------------
// Configuration flags (module-level defaults, overridden in init())
//
// Every toggle below has a source-level default declared here, and is
// optionally overridden at init() time by a matching key in Gadget's
// `interaction.parameters` object (libfrida-gadget.config.so). This
// lets the same script run under three deployment styles:
//
//   1. Gadget + config file (recommended for iterative work):
//      flags and value maps are driven entirely by
//      libfrida-gadget.config.so; nothing in this file needs editing.
//
//   2. Direct-script use — frida CLI attach (`frida -U -f <pkg> -l
//      this-script.js`), Gadget without a config file, or any other
//      invocation that supplies no parameters: every flag uses the
//      default declared below. To enable a module, edit its default
//      from `false` to `true` in this file and recompile with
//      frida-compile.
//
//   3. Hybrid: defaults here act as a baseline; config overrides
//      only the keys it explicitly sets. A parameter key present in
//      config always wins over the source-level default; a key
//      absent from config leaves the default intact.
//
// Naming convention: booleans end in `Enabled` and gate a module; the
// companion `*Values` object immediately below (when present) supplies
// that module's runtime values and is ignored while its flag is false.
//
// The three config-driven arrays (defaultJavaHooks, nativeHooks,
// nativePatches) carry their full schema and examples inline at each
// declaration below.
// ------------------------------------------------------------------

/** Enables logcat output for this engine. Overridden by parameters.debugLog. */
let debugLoggingEnabled = false;

/** Enables the installer-source spoofing module. Overridden by parameters.installerSpoofEnabled. */
let installerSpoofEnabled = false;

/** Enables the ADB / Developer Options detection bypass module. Overridden by parameters.adbDevSettingsBypassEnabled. */
let adbDevSettingsBypassEnabled = false;

/** Enables the mock-location detection bypass module. Overridden by parameters.mockLocationBypassEnabled. */
let mockLocationBypassEnabled = false;

/** Enables the auto-time / auto-timezone spoofing module — forces Settings.Global "auto_time" and "auto_time_zone" to always report "1" (automatic mode). Apps reading these keys see a device whose clock is not manually managed, a common tamper-detection signal. Overridden by parameters.autoTimeSpoofEnabled. */
let autoTimeSpoofEnabled = false;

/** Enables the PairIP license-check NOP module — replaces com.pairip.licensecheck.LicenseClient.bindToLicensingService(boolean) with an empty implementation; this prevents the app from binding to the PairIP licensing service. Provided as a dedicated toggle (rather than a javaHooks entry) because the target is fixed and the config surface stays minimal. Overridden by parameters.pairipLicenseBypassEnabled. */
let pairipLicenseBypassEnabled = false;

/** Enables the FLAG_SECURE screenshot/screen-recording restriction bypass module. Overridden by parameters.flagSecureBypassEnabled. */
let flagSecureBypassEnabled = false;

/** Enables the VPN/proxy detection bypass module. Overridden by parameters.vpnProxyBypassEnabled. */
let vpnProxyBypassEnabled = false;

/** Enables the SSL/TLS certificate-pinning bypass module. Covers two independent layers: the Android Java/Kotlin TLS stack (SSLContext, TrustManagerFactory, HttpsURLConnection, OkHttp CertificatePinner, Android Network Security Config, TrustKit, Appmattus CT) and the native Flutter/BoringSSL bypass for libflutter.so when that module is loaded. Overridden by parameters.sslPinningBypassEnabled. */
let sslPinningBypassEnabled = false;

/** Enables the geo-restriction bypass module (carrier/network identity). Overridden by parameters.geoRestrictionBypassEnabled. */
let geoRestrictionBypassEnabled = false;

/** Carrier/network identity values used by the geo-restriction bypass module. Overridden per-key by parameters.geoSpoofValues. */
let geoSpoofValues = {
  operatorName: "AT&T",
  plmn: "310410",
  countryIso: "us"
};

/** Enables the locale/timezone spoofing module. Overridden by parameters.localeSpoofEnabled. */
let localeSpoofEnabled = false;

/** Locale/timezone values used by the locale spoofing module. Overridden per-key by parameters.localeSpoofValues. */
let localeSpoofValues = {
  country: "US",
  language: "en",
  timezoneId: "America/New_York"
};

/** Enables the suspicious-package (root/patcher/Xposed/emulator) hiding module. Overridden by parameters.suspiciousPackageSpoofEnabled. */
let suspiciousPackageSpoofEnabled = false;

/** Suspicious package names to hide. Overridden by parameters.suspiciousPackagesCustom. */
let suspiciousPackagesCustom = [
  "bin.mt.plus",
  "com.network.proxy",
  "com.termux"
];

/** Enables the fake-installed-package module — makes listed packages appear installed across PackageManager lookups and enumeration, even though they aren't actually present on the device. The inverse of suspiciousPackageSpoofEnabled. Overridden by parameters.installedPackageSpoofEnabled. */
let installedPackageSpoofEnabled = false;

/** Per-package fabricated identity for the fake-installed-package module. Keys are package names; values are optional-field config objects (all fields strings). Overridden (per-package, per-field) by parameters.installedPackageSpoofValues. */
let installedPackageSpoofValues = {
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
};

/** Enables the device-identifier spoofing module. Overridden by parameters.deviceIdSpoofEnabled. */
let deviceIdSpoofEnabled = false;

/** Selects randomly-generated values over deviceIdSpoofValues. Overridden by parameters.deviceIdSpoofUseRandom. */
let deviceIdSpoofUseRandom = false;

/** Fixed device-identifier values, used when deviceIdSpoofUseRandom is false. Overridden per-key by parameters.deviceIdSpoofValues. */
let deviceIdSpoofValues = {
  androidId: "a1b2c3d4e5f6a7b8",
  imei: "356938035643809",
  meid: "A1000012B3C456",
  iccid: "89014103211118510720",
  imsi: "310260123456789",
  phoneNumber: "+15555215556",
  wifiMac: "3C:5A:B4:1E:2F:8D",
  bluetoothMac: "AC:37:43:2B:9C:14",
  advertisingId: "38400000-8cf0-11bd-b23e-10b96e40000d",
  internalIp: "192.168.1.42"
};

/** Enables the build-prop (Tier-A device-identity) spoofing module. Overridden by parameters.buildPropSpoofEnabled. */
let buildPropSpoofEnabled = false;

/** Tier-A device-identity field values. Overridden per-key by parameters.buildPropSpoofValues. */
let buildPropSpoofValues = {
  manufacturer: "Google",
  model: "Pixel 7 Pro",
  brand: "google",
  product: "cheetah",
  device: "cheetah",
  hardware: "cheetah",
  board: "cheetah",
  bootloader: "unknown",
  host: "android-build",
  id: "AP4A.241205.013",
  fingerprint: "google/cheetah/cheetah:15/AP4A.241205.013/12621605:user/release-keys",
  tags: "release-keys",
  type: "user",
  user: "android-build",
  display: "AP4A.241205.013",
  release: "15",
  securityPatch: "2024-12-05",
  incremental: "12621605",
  codename: "REL"
};

/** Enables the SystemProperties spoofing module. Overridden by parameters.systemPropertySpoofEnabled. */
let systemPropertySpoofEnabled = false;

/** Spoofed system-property key/value map (open-ended — any ro., persist., or qemu. key may be added). Overridden per-key by parameters.systemPropertySpoofValues. */
let systemPropertySpoofValues = {
  "ro.boot.verifiedbootstate": "green",
  "ro.boot.flash.locked": "1",
  "ro.oem_unlock_supported": "0",
  "ro.secureboot.lockstate": "locked",
  "ro.kernel.qemu": "0",
  "ro.boot.qemu": "0",
  "ro.hardware": "cheetah",
  "ro.secure": "1",
  "ro.debuggable": "0",
  "ro.allow.mock.location": "0",
  "qemu.hw.mainkeys": "1"
};

/** Enables the hardware-feature spoofing module. Overridden by parameters.hardwareFeatureSpoofEnabled. */
let hardwareFeatureSpoofEnabled = false;

/** Feature strings PackageManager.hasSystemFeature() reports as present regardless of actual state. Overridden by parameters.spoofedHardwareFeatures. */
let spoofedHardwareFeatures = [
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
];

/** Enables the ContentResolver.query()/call() spoofing module (Settings + GSF providers). Overridden by parameters.contentProviderSpoofEnabled. */
let contentProviderSpoofEnabled = false;

/** Per-authority key/value maps ContentResolver.query()/call() spoofing draws from. The "settings" authority's map is merged with the ADB/mock-location/android_id keys derived from other flags at apply time — see its construction in init(). Overridden (per-authority, per-key) by parameters.contentProviderSpoofValues. */
let contentProviderSpoofValues = {
  settings: {
    development_settings_enabled: "0",
    adb_enabled: "0",
    mock_location: "0",
    android_id: "a1b2c3d4e5f6a7b8"
  },
  "com.google.android.gsf.gservices": {
    android_id: "3f9d0a2b4c5e6f71"
  }
};

/** Enables the config-driven Java hooking module. Overridden by parameters.javaHooksEnabled. */
let javaHooksEnabled = false;

/**
 * Default config-driven Java hook definitions, used when
 * parameters.javaHooks is absent or invalid — e.g. under Listen mode,
 * where no Gadget-supplied parameters exist. Overridden by
 * parameters.javaHooks.
 *
 * Each entry hooks one overload of one Java method. Multiple overloads
 * require multiple entries. Entries install with bounded retry (10
 * attempts at 500 ms), scheduled via setTimeout so app startup is
 * never blocked.
 *
 * Schema (per entry):
 *   className    REQUIRED — fully-qualified Java name with dots,
 *                e.g. "com.example.Foo" (never JNI form "Lcom/...").
 *   methodName   REQUIRED — exact method name as declared.
 *   argTypes     OPTIONAL — required when the method has multiple
 *                overloads. Java source form for primitives
 *                ("boolean", "int", "long"); JNI form for arrays
 *                ("[B", "[Ljava.lang.String;"). JNI primitive forms
 *                ("Z", "I") are NOT accepted here — use the word forms.
 *   returnType   OPTIONAL — used only to coerce forceReturn and to
 *                detect void; not used by overload resolution.
 *                Accepts both word form ("void", "int") and JNI
 *                primitive form ("V", "I"); arrays use JNI form.
 *   onCall       OPTIONAL — absent = observe only (original runs).
 *                Sub-keys:
 *                  logArgs      log every arg with its declared type
 *                  logReturn    log the original return
 *                  modifyArgs   { "<0-based idx>": <value> } — args
 *                               coerced via argTypes[idx]
 *                  nop          skip the original implementation
 *                  forceReturn  override the return (applied after
 *                               the original unless nop is also set)
 *
 * Pairing rules:
 *   nop + non-void + no forceReturn → returns undefined at the JNI
 *   boundary; supply forceReturn instead.
 *   modifyArgs without nop → original still runs and sees the
 *   modified args.
 *   forceReturn without nop → original runs (side effects happen);
 *   only the return value is overridden.
 *
 * Examples (edit and place inside the array literal):
 *
 *   // Silence a void method call:
 *   { className: 'com.example.Logger', methodName: 'writeLog',
 *     argTypes: ['java.lang.String'], returnType: 'void',
 *     onCall: { logArgs: true, nop: true } },
 *
 *   // Bypass a boolean check (single overload — argTypes omitted):
 *   { className: 'com.example.RootChecker', methodName: 'isDeviceRooted',
 *     returnType: 'boolean',
 *     onCall: { logReturn: true, nop: true, forceReturn: false } },
 *
 *   // Return a spoofed String:
 *   { className: 'com.example.Utils', methodName: 'getDeviceId',
 *     argTypes: [], returnType: 'java.lang.String',
 *     onCall: { logReturn: true,
 *               forceReturn: '00000000-0000-0000-0000-000000000000' } },
 *
 *   // Modify one argument then force the return (multi-overload —
 *   // argTypes required to disambiguate):
 *   { className: 'com.example.LicenseManager', methodName: 'isValidLicense',
 *     argTypes: ['java.lang.String', 'int'], returnType: 'boolean',
 *     onCall: { logArgs: true, logReturn: true,
 *               modifyArgs: { '1': 9999 }, forceReturn: true } }
 */
let defaultJavaHooks = [];

/** Enables the config-driven native (.so-level) hooking module. Overridden by parameters.nativeHooksEnabled. */
let nativeHooksEnabled = false;

/**
 * Native hook definitions — see resolveTargetAddress() /
 * applyTypedNativeHook() / applyRawNativeHook() for the runtime
 * implementation. Overridden by parameters.nativeHooks.
 *
 * Two modes, selected per entry:
 *   Typed mode — both argTypes AND returnType present. Full type
 *                safety, chains to the original via NativeFunction,
 *                supports onCall.nop.
 *   Raw mode   — otherwise. Pointer-sized args/return only. onCall.nop
 *                is ignored with a warning (attach cannot skip the
 *                call it observes).
 *
 * Schema (per entry):
 *   moduleName       REQUIRED — e.g. "libc.so", "libtarget.so". Must
 *                    already be loaded when the hook is installed.
 *   Target locator   REQUIRED — exactly ONE of:
 *     symbolName       exported symbol name (ASLR-safe; best choice)
 *     offset           hex string offset from module base, e.g.
 *                      "0x1234" (ASLR-safe; use for non-exported
 *                      functions located via reverse engineering)
 *     absoluteAddress  raw pointer (NOT ASLR-safe; testing only)
 *   argTypes         typed mode only. Array of Frida native type
 *                    strings: "void" "bool" "int8" "uint8" "int16"
 *                    "uint16" "int32" "uint32" "int64" "uint64" "int"
 *                    "uint" "char" "uchar" "float" "double" "pointer".
 *   returnType       typed mode only. Single type from the list above.
 *   onCall           OPTIONAL. Same sub-keys as javaHooks, except that
 *                    modifyArgs values are coerced via argTypes and
 *                    forceReturn via returnType, both using Frida
 *                    native type rules. int64 / uint64 values should
 *                    be supplied as strings for anything beyond 2^53.
 *   rawArgCount      OPTIONAL, raw mode only (ignored in typed mode,
 *                    which already knows its arity from argTypes). How
 *                    many pointer-sized arg slots onCall.logArgs logs.
 *                    Non-negative integer; defaults to 4 if omitted.
 *
 * Examples (edit and place inside the array literal):
 *
 *   // Typed — void return, no args (observe only):
 *   { moduleName: 'libc.so', symbolName: 'srand',
 *     argTypes: [], returnType: 'void',
 *     onCall: { logArgs: true } },
 *
 *   // Typed — int return forced to 1 (original still runs):
 *   { moduleName: 'libtarget.so', offset: '0x1234',
 *     argTypes: ['int'], returnType: 'int',
 *     onCall: { logArgs: true, forceReturn: 1 } },
 *
 *   // Raw — pointer-sized observe only (no argTypes/returnType):
 *   { moduleName: 'libc.so', symbolName: 'malloc',
 *     onCall: { logArgs: true, logReturn: true } }
 */
let nativeHooks = [];

/** Enables the native code-patching module (Memory.patchCode()). Overridden by parameters.nativePatchesEnabled. */
let nativePatchesEnabled = false;

/**
 * Native patch definitions — see applyNativePatches() for the runtime
 * implementation. Overridden by parameters.nativePatches.
 *
 * Direct instruction-byte edits at a specific address — not a function
 * hook. The engine cannot validate that the bytes are well-formed for
 * the target CPU architecture; a malformed patch can corrupt execution.
 * Original bytes are captured before patching and restored verbatim on
 * revert.
 *
 * Schema (per entry):
 *   moduleName       REQUIRED — same rule as nativeHooks.
 *   Target locator   REQUIRED — exactly ONE of symbolName / offset /
 *                    absoluteAddress (same rules as nativeHooks).
 *   patchBytes       REQUIRED — accepts two equivalent forms:
 *                      ['1F', '20', '03', 'D5']  array of 2-char hex
 *                                                byte strings
 *                      '1F2003D5'                single concatenated
 *                                                hex string
 *                    The string form must be non-empty and even-length;
 *                    a malformed string is rejected before any memory
 *                    is written, so no partial patch is ever applied.
 *
 * Common ARM64 idioms:
 *   NOP               1F 20 03 D5
 *   RET               C0 03 5F D6
 *   MOV W0, #0 ; RET  00 00 80 D2  C0 03 5F D6
 *   MOV W0, #1 ; RET  20 00 80 52  C0 03 5F D6
 *
 * Examples (edit and place inside the array literal):
 *
 *   // NOP — array form:
 *   { moduleName: 'libtarget.so', offset: '0x2A10',
 *     patchBytes: ['1F', '20', '03', 'D5'] },
 *
 *   // MOV W0,#1 ; RET — array form:
 *   { moduleName: 'libtarget.so', offset: '0x5678',
 *     patchBytes: ['20', '00', '80', '52', 'C0', '03', '5F', 'D6'] },
 *
 *   // MOV W0,#1 ; RET — string form (equivalent to the array above):
 *   { moduleName: 'libtarget.so', offset: '0x5678',
 *     patchBytes: '20008052C0035FD6' }
 */
let nativePatches = [];

/**
 * Enables the RegisterNatives discovery/logging module.
 * Overridden by parameters.registerNativesLogEnabled.
 *
 * Credit: Module concept and implementation contributed by Marc Nin (@mragonias).
 */
let registerNativesLogEnabled = false;

/** 
 * Class names to restrict logging to; empty (the default) logs every 
 * RegisterNatives call process-wide — including system/Play Services 
 * libraries, not only the target app, which can be noisy. 
 * Overridden by parameters.registerNativesLogClassFilter. 
 */
let registerNativesLogClassFilter = [];

/**
 * Optional manual override for locating RegisterNatives in libart.so,
 * for when the default symbol-name heuristic in applyRegisterNativesLog()
 * finds zero matches (symbols stripped on this build) or more than one
 * candidate (picks the wrong one for this ART version). Exactly one of
 * symbolName/offset is used if set; both empty means "use the heuristic".
 * Overridden per-key by parameters.registerNativesLogLocator.
 */
let registerNativesLogLocator = { symbolName: "", offset: "" };



// ════════════════════════════════════════════════
//                   E N D   C O N F I G U R A T I O N                
// ════════════════════════════════════════════════



// ------------------------------------------------------------------
// Logging
//
// Dual-output routing:
// 1. console.log() — visible immediately in the terminal for users
//    running via Frida CLI (spawn/attach) or Gadget Listen mode.
// 2. android.util.Log — visible via `adb logcat -s FridaHookEngine:V`
//    for users running in Gadget Script mode (no attached controller).
//
// Both are fired simultaneously. The android.util.Log call is wrapped
// in a try/catch because Java.use() requires VM access; if a log fires
// before the VM is fully attached during early startup, the console.log
// above it still guarantees the message is emitted to any attached
// controller, preventing silent failures.
// ------------------------------------------------------------------
const LOG_TAG = 'FridaHookEngine';

let AndroidLog = null; // resolved lazily; Java.use requires VM access

function log(level, message) {
  if (!debugLoggingEnabled) return;
  
  // Console output — visible to attached controller (spawn/listen)
  console.log(`[${LOG_TAG}] ${message}`);
 
  // Logcat output — visible via adb logcat (all modes)
  try {
    if (!AndroidLog) {
      AndroidLog = Java.use('android.util.Log');
    }
    AndroidLog[level](LOG_TAG, message);
  } catch (e) {
    // VM not attached yet; console.log above already emitted it.
  }
}

const logD = (msg) => log('d', msg);
const logI = (msg) => log('i', msg);
const logW = (msg) => log('w', msg);
const logE = (msg) => log('e', msg);

// ------------------------------------------------------------------
// Hook bookkeeping — enables dispose() to restore original method
// implementations on script unload or Gadget-triggered reload.
// ------------------------------------------------------------------
const appliedHooks = []; // { target: Method, originalImpl: Function|null }

// Field-mutation bookkeeping for the build-prop module's dispose()-time
// reversion — separate from appliedHooks since these are static field
// writes (BuildClass.FIELD.value = ...), not method-implementation
// replacements.
const originalBuildPropFieldValues = {}; // fieldName ('VERSION.'-prefixed for Build$VERSION) -> original value
const appliedBuildMethodHooks = [];       // overload targets, for Build.getSerial/getRadioVersion
const appliedSystemPropertyHooks = [];    // overload targets, for SystemProperties.get overloads
const appliedDeviceIdHooks = [];          // overload targets, for device-identifier method hooks
const appliedHardwareFeatureHooks = [];   // overload targets, for hasSystemFeature overloads
const appliedContentProviderHooks = [];   // ContentResolver/ContentProviderClient query()/call() hook targets
const appliedTypedNativeHookAddresses = []; // NativePointer[], reverted via Interceptor.revert()
const appliedRawNativeHookListeners = [];   // InvocationListener[], reverted via .detach()
const appliedRegisterNativesListeners = []; // InvocationListener[], reverted via .detach()
const appliedNativePatches = [];            // { address, originalBytes }

// Bookkeeping for the modules below that predate the applied*Hooks
// convention above (and the three added after it) — each previously set
// `.implementation = fn` directly with no tracked target, so dispose()
// had no way to revert them. Same convention as appliedHooks/
// appliedDeviceIdHooks/etc.: push the resolved overload target right
// after assigning its .implementation, revert with `.implementation = null`.
const appliedSecureSettingsHooks = [];    // overload targets, for applySecureSettingsSpoof() (shared by ADB/mock-location/auto-time/android_id)
const appliedInstallerHooks = [];         // overload targets, for applyInstallerSpoof()
const appliedFlagSecureHooks = [];        // overload targets, for applyFlagSecureBypass()
const appliedVpnProxyHooks = [];          // overload targets, for applyVpnProxyDetectionBypass()
const appliedGeoHooks = [];               // overload targets, for applyGeoRestrictionBypass()
const appliedLocaleHooks = [];            // overload targets, for applyLocaleSpoof()'s method-hook half
let originalDefaultLocale = null;         // captured Locale, for applyLocaleSpoof()'s Locale.setDefault() mutation half
let originalDisplayLocale = null;         // captured Locale, for the DISPLAY category default
let originalFormatLocale = null;          // captured Locale, for the FORMAT category default
const appliedSuspiciousPackageHooks = []; // overload targets, for applySuspiciousPackageSpoofing()
const appliedMockLocationHooks = [];      // overload targets, for applyMockLocationBypass()
const appliedPairipHooks = [];            // overload targets, for applyPairipLicenseBypass()
const appliedInstalledPackageHooks = [];  // overload targets, for applyInstalledPackageSpoof()
const appliedSslJavaHooks = [];           // overload targets, for applySslPinningBypass()'s Java/Kotlin layer
const appliedSslNativeAddresses = [];     // InvocationListener[], for applySslPinningBypass()'s Flutter/BoringSSL Interceptor.attach hook — reverted via .detach()

/**
 * Serializes a value for logging without permitting a failing
 * toString() implementation to abort hook execution.
 */
function safeStringify(val) {
  if (val === null || val === undefined) return String(val);
  try {
    if (Array.isArray(val)) return `[Array len=${val.length}]`;
    return val.toString();
  } catch (e) {
    return `<unstringifiable: ${e.message}>`;
  }
}

function isVoidType(type) {
  return type === 'void' || type === 'V';
}

/**
 * Lazily-cached java.lang.* wrapper class references, populated on
 * first use inside coerceValueForType(). Java.use() is cheap but not
 * free, and this avoids re-resolving the same class on every hook
 * invocation. Safe to call from here without an explicit Java.perform
 * wrapper: coerceValueForType() only ever runs from a thread that is
 * already JVM-attached — either inside a hooked method's own
 * implementation (attached by definition, since the original method
 * call arrived there) or from applyJavaHook()'s nop/forceReturn path,
 * which executes in that same context.
 */
const wrapperClassCache = {};
function getWrapperClass(className) {
  if (!wrapperClassCache[className]) {
    wrapperClassCache[className] = Java.use(className);
  }
  return wrapperClassCache[className];
}

/**
 * Coerces a JSON configuration value into the representation expected
 * by the declared Java/Kotlin type, for use as either an argument or
 * a return value.
 *
 * Primitive types (boolean, int, long, ...) convert to plain JS
 * values — Frida's own argument/return marshalling handles the JNI
 * conversion for those automatically. Boxed wrapper types
 * (java.lang.Boolean, java.lang.Integer, ...) do NOT get this
 * treatment from Frida: autoboxing is a javac bytecode-generation
 * feature, not a JVM/ART runtime behavior, so a method whose declared
 * type is a wrapper class must be handed an actual boxed object —
 * passing a bare JS boolean/number where a java.lang.Boolean/Integer
 * is expected fails at the JNI boundary. This matters in practice
 * because Kotlin's nullable primitives (Boolean?, Int?, Long?,
 * Double?) compile to exactly these wrapper types, so hooking a
 * Kotlin-compiled method commonly means hitting this path.
 */
function coerceValueForType(type, rawValue) {
  if (isVoidType(type)) return undefined;

  switch (type) {
    case 'boolean':
    case 'Z':
      return !!rawValue;

    case 'byte':
    case 'B':
    case 'short':
    case 'S':
    case 'int':
    case 'I':
      return rawValue | 0;

    case 'long':
    case 'J':
      // Values exceeding JavaScript's safe integer range should be
      // supplied as strings in the configuration to preserve precision.
      return typeof rawValue === 'string'
        ? Java.use('java.lang.Long').parseLong(rawValue)
        : rawValue;

    case 'float':
    case 'F':
    case 'double':
    case 'D':
      return typeof rawValue === 'number' ? rawValue : parseFloat(rawValue);

    case 'char':
    case 'C':
      // Java char is a single UTF-16 code unit; Frida represents it as
      // a 1-character JS string on both the read and write side. A
      // malformed config value is caught here rather than silently
      // forwarded to the JNI boundary.
      if (typeof rawValue !== 'string' || rawValue.length !== 1) {
        logW(`[coerceValueForType] 'char' expects a 1-character string, got ${safeStringify(rawValue)} — using '\\u0000'`);
        return '\u0000';
      }
      return rawValue;

    case 'java.lang.String':
      return rawValue === null ? null : String(rawValue);

    // --- Boxed wrapper types — require explicit boxing (see doc above) ---

    case 'java.lang.Boolean':
      return rawValue === null ? null : getWrapperClass('java.lang.Boolean').valueOf(!!rawValue);

    case 'java.lang.Byte':
      return rawValue === null ? null : getWrapperClass('java.lang.Byte').valueOf(rawValue | 0);

    case 'java.lang.Short':
      return rawValue === null ? null : getWrapperClass('java.lang.Short').valueOf(rawValue | 0);

    case 'java.lang.Integer':
      return rawValue === null ? null : getWrapperClass('java.lang.Integer').valueOf(rawValue | 0);

    case 'java.lang.Long':
      if (rawValue === null) return null;
      return getWrapperClass('java.lang.Long').valueOf(
        typeof rawValue === 'string'
          ? Java.use('java.lang.Long').parseLong(rawValue)
          : rawValue
      );

    case 'java.lang.Float':
      if (rawValue === null) return null;
      return getWrapperClass('java.lang.Float').valueOf(
        typeof rawValue === 'number' ? rawValue : parseFloat(rawValue)
      );

    case 'java.lang.Double':
      if (rawValue === null) return null;
      return getWrapperClass('java.lang.Double').valueOf(
        typeof rawValue === 'number' ? rawValue : parseFloat(rawValue)
      );

    case 'java.lang.Character':
      if (rawValue === null) return null;
      if (typeof rawValue !== 'string' || rawValue.length !== 1) {
        logW(`[coerceValueForType] java.lang.Character expects a 1-character string, got ${safeStringify(rawValue)} — using '\\u0000'`);
        return getWrapperClass('java.lang.Character').valueOf('\u0000');
      }
      return getWrapperClass('java.lang.Character').valueOf(rawValue);

    default:
      // Object types (custom classes) and arrays are passed through
      // unmodified. Arrays are deliberately left to Frida's own
      // argument/return marshalling, which already converts plain JS
      // arrays to/from Java arrays based on the declared signature.
      // Forcing a return value of a custom object type requires
      // construction logic specific to that class and is outside this
      // generic path — see the javaHooks schema doc above
      // applyJavaHook() for the documented scope of this limitation.
      return rawValue;
  }
}

/**
 * Resolves a method reference to a specific overload when argTypes are
 * supplied, or to the unqualified method group otherwise.
 *
 * Omitting argTypes against a method group that actually has more than
 * one overload is valid Frida usage — assigning .implementation to an
 * unresolved group hooks every overload with the same function — but
 * it is rarely what a config author intends, since the same declared
 * returnType then gets used to coerce forceReturn/modifyArgs for every
 * overload, which silently produces wrong values for any overload
 * whose real return type differs. className is passed through purely
 * for a clearer warning message.
 */
function resolveOverload(className, target, methodName, argTypes) {
  const methodGroup = target[methodName];
  if (!methodGroup) {
    throw new Error(`Method not found: ${methodName}`);
  }
  if (!argTypes || argTypes.length === 0) {
    const overloadCount = Array.isArray(methodGroup.overloads) ? methodGroup.overloads.length : 1;
    if (overloadCount > 1) {
      logW(`[resolveOverload] ${className}.${methodName} has ${overloadCount} overloads but argTypes ` +
           `was omitted — hooking ALL of them with one implementation and one declared returnType. ` +
           `If the overloads don't all share that return type, forceReturn/modifyArgs coercion will ` +
           `be wrong for the mismatched ones. Supply argTypes to target a single overload.`);
    }
    return methodGroup;
  }
  return methodGroup.overload(...argTypes);
}

/**
 * Applies a single hook definition from the configuration's javaHooks
 * array: resolves the target overload, installs a replacement
 * implementation honoring the declared onCall behavior (argument
 * logging/modification, return logging/forcing, or unconditional
 * bypass of the original implementation), and records the original
 * implementation for later reversal.
 */
function applyJavaHook(hookConfig) {
  const { className, methodName, argTypes = [], returnType, onCall = {} } = hookConfig;

  const target = Java.use(className);
  const boundMethod = resolveOverload(className, target, methodName, argTypes);
  const voidReturn = isVoidType(returnType);
  const originalImpl = boundMethod.implementation;

  boundMethod.implementation = function (...args) {
    const tag = `${className}.${methodName}`;
  
    // Pre-original phase — argument logging and mutation. Guarded
    // separately from the original call so that a failure here
    // falls through to the original with (possibly mutated) args,
    // rather than aborting the call entirely. If the original runs
    // and then the post-original phase fails, retrying the original
    // would double its side effects — so the two phases are split
    // deliberately instead of wrapping the whole body in one block.
    try {
      if (onCall.logArgs) {
        if (args.length === 0) {
          logD(`[${tag}] (no args)`);
        }
        args.forEach((a, i) => {
          const t = argTypes[i] || '?';
          logD(`[${tag}] arg[${i}] (${t}) = ${safeStringify(a)}`);
        });
      }
  
      if (onCall.modifyArgs) {
        for (const [idxStr, newVal] of Object.entries(onCall.modifyArgs)) {
          const idx = parseInt(idxStr, 10);
          const t = argTypes[idx];
          const coerced = coerceValueForType(t, newVal);
          logD(`[${tag}] overriding arg[${idx}] (${t}) -> ${safeStringify(coerced)}`);
          args[idx] = coerced;
        }
      }
    } catch (preErr) {
      logE(`[${tag}] pre-call processing threw: ${preErr.message}`);
      // Fall through to original — args may be partially mutated.
    }
  
    // Unconditional bypass of the original implementation. Independent
    // of modifyArgs: argument modification above still applies even
    // when nop is set, though it has no observable effect unless the
    // caller inspects the (mutated) argument objects itself.
    if (onCall.nop) {
      logD(`[${tag}] NOP — original implementation skipped`);
      if (voidReturn) return undefined;
      if (Object.prototype.hasOwnProperty.call(onCall, 'forceReturn')) {
        try {
          return coerceValueForType(returnType, onCall.forceReturn);
        } catch (nopErr) {
          logE(`[${tag}] nop forceReturn coercion threw: ${nopErr.message}`);
          return undefined;
        }
      }
      return undefined;
    }
  
    // Original call — intentionally unguarded. An exception thrown by
    // the original is the app's own behavior and must propagate to the
    // caller, not be swallowed by this engine.
    const result = this[methodName].apply(this, args);
  
    // Post-original phase — return logging and forced return. Guarded
    // separately so that a failure here returns the original result
    // instead of retrying the original (which would double side effects).
    try {
      if (onCall.logReturn && !voidReturn) {
        logD(`[${tag}] original return = ${safeStringify(result)}`);
      }
  
      if (!voidReturn && Object.prototype.hasOwnProperty.call(onCall, 'forceReturn')) {
        const forced = coerceValueForType(returnType, onCall.forceReturn);
        logD(`[${tag}] forced return -> ${safeStringify(forced)}`);
        return forced;
      }
    } catch (postErr) {
      logE(`[${tag}] post-call processing threw: ${postErr.message}`);
    }
  
    return voidReturn ? undefined : result;
  };

  appliedHooks.push({ target: boundMethod, originalImpl });
}

/**
 * Applies a hook definition with bounded retry, accommodating the
 * case where the target class has not yet been loaded by the Android
 * Runtime at the time init() is invoked. Retries are scheduled via
 * setTimeout and therefore do not extend the synchronous execution
 * time of init(), which Gadget waits on before releasing the host
 * application's entrypoint.
 */
function applyHookWithRetry(hookConfig, attempt = 0) {
  const MAX_ATTEMPTS = 10;
  const RETRY_DELAY_MS = 500;

  try {
    applyJavaHook(hookConfig);
    logI(`[+] Hooked ${hookConfig.className}.${hookConfig.methodName}`);
  } catch (e) {
    if (attempt < MAX_ATTEMPTS) {
      logW(`[~] Retry ${attempt + 1}/${MAX_ATTEMPTS} for ${hookConfig.className}.${hookConfig.methodName}: ${e.message}`);
      setTimeout(() => applyHookWithRetry(hookConfig, attempt + 1), RETRY_DELAY_MS);
    } else {
      logE(`[-] Failed to hook ${hookConfig.className}.${hookConfig.methodName} after ${MAX_ATTEMPTS} attempts: ${e.message}`);
    }
  }
}

function applyAllJavaHooks(hooks) {
  Java.perform(function () {
    logI(`[*] Loading ${hooks.length} Java hook(s)...`);
    for (const hook of hooks) {
      applyHookWithRetry(hook);
    }
  });
}

function revertAllHooks() {
  Java.perform(function () {
    logI(`[*] Reverting ${appliedHooks.length} applied hook(s)...`);
    for (const { target, originalImpl } of appliedHooks) {
      try {
        target.implementation = originalImpl;
      } catch (e) {
        logE(`[-] Failed to revert a hook: ${e.message}`);
      }
    }
    appliedHooks.length = 0;
  });
}

/**
 * Secure/Global/System settings-key spoofing (shared utility).
 *
 * Forces Settings.Secure, Settings.Global, and Settings.System lookups
 * of any key in keyValues to return the mapped value, across the
 * getInt(3-arg), getInt(2-arg), and getString overloads. For getInt,
 * the mapped string is parsed as an integer (falling back to 0 if it
 * isn't numeric, which is harmless for a key like android_id that no
 * legitimate caller would query via getInt in the first place).
 * Settings.System has no independent constant for keys that were
 * introduced directly in Settings.Secure (e.g.
 * development_settings_enabled), but its getInt/getString are hooked
 * regardless as a low-cost safeguard, since redirect behavior for
 * MOVED_TO_GLOBAL/MOVED_TO_SECURE keys has varied across API levels
 * and OEM ROMs.
 *
 * This is a single, shared installation point rather than one hook
 * per feature: Frida's method-implementation assignment replaces any
 * prior implementation on the same method rather than chaining, so
 * two independently-installed hooks on the same Settings getter would
 * silently disable one another. Callers therefore pass the full,
 * combined key/value map across every enabled feature that depends on
 * Settings interception (see its construction in init()), and this
 * function is invoked at most once per session.
 *
 * References:
 *   https://developer.android.com/reference/android/provider/Settings.Secure
 *   https://developer.android.com/reference/android/provider/Settings.Global
 *   https://developer.android.com/reference/android/provider/Settings.System
 */
function applySecureSettingsSpoof(keyValues) {
  function patchSettingsProvider(className) {
    try {
      var SettingsClass = Java.use(className);

      // getInt with default value (3 args).
      try {
        const getInt3Target = SettingsClass.getInt.overload('android.content.ContentResolver', 'java.lang.String', 'int');
        getInt3Target.implementation = function (cr, name, def) {
          if (Object.prototype.hasOwnProperty.call(keyValues, name)) {
            const parsed = parseInt(keyValues[name], 10);
            return isNaN(parsed) ? 0 : parsed;
          }
          return this.getInt(cr, name, def);
        };
        appliedSecureSettingsHooks.push(getInt3Target);
        logI("[+] " + className + ".getInt (3 args) hooked.");
      } catch (e) {
        logW("[!] " + className + ".getInt (3 args) hook failed: " + e);
      }

      // getInt without a default value (2 args); throws
      // SettingNotFoundException if the key is absent.
      try {
        const getInt2Target = SettingsClass.getInt.overload('android.content.ContentResolver', 'java.lang.String');
        getInt2Target.implementation = function (cr, name) {
          if (Object.prototype.hasOwnProperty.call(keyValues, name)) {
            const parsed = parseInt(keyValues[name], 10);
            return isNaN(parsed) ? 0 : parsed; // Prevents the exception from being thrown for these keys.
          }
          return this.getInt(cr, name);
        };
        appliedSecureSettingsHooks.push(getInt2Target);
        logI("[+] " + className + ".getInt (2 args) hooked.");
      } catch (e) {
        logW("[!] " + className + ".getInt (2 args) hook failed: " + e);
      }

      // getString — some callers parse the string representation
      // ("1"/"0", "true"/"false") rather than calling getInt.
      try {
        const getStringTarget = SettingsClass.getString.overload('android.content.ContentResolver', 'java.lang.String');
        getStringTarget.implementation = function (cr, name) {
          if (Object.prototype.hasOwnProperty.call(keyValues, name)) {
            return keyValues[name];
          }
          return this.getString(cr, name);
        };
        appliedSecureSettingsHooks.push(getStringTarget);
        logI("[+] " + className + ".getString hooked.");
      } catch (e) {
        logW("[!] " + className + ".getString hook failed: " + e);
      }

    } catch (err) {
      logE("[!] Failed to access class " + className + ": " + err);
    }
  }

  patchSettingsProvider("android.provider.Settings$Secure");
  patchSettingsProvider("android.provider.Settings$Global");
  patchSettingsProvider("android.provider.Settings$System");

  logI(`[*] Settings overloads patched for keys: ${Object.keys(keyValues).join(", ")}`);
}

function revertSecureSettingsSpoof() {
  for (const target of appliedSecureSettingsHooks) {
    try {
      target.implementation = null;
    } catch (err) {
      logW('[!] Failed to revert a Settings hook: ' + err);
    }
  }
  appliedSecureSettingsHooks.length = 0;
  logI('[*] Settings$Secure/Global/System spoofing reverted.');
}

/**
 * Installer-source spoofing.
 *
 * Forces the calling app's recorded installation source to appear as
 * the Google Play Store package ("com.android.vending") across both
 * the deprecated single-value API and the current three-field API:
 *
 *   - PackageManager.getInstallerPackageName(String)  [deprecated in API 30]
 *   - InstallSourceInfo.getInstallingPackageName()    [API 30+]
 *   - InstallSourceInfo.getInitiatingPackageName()    [API 30+]
 *   - InstallSourceInfo.getOriginatingPackageName()   [API 30+]
 *
 * All three InstallSourceInfo fields are spoofed together, since a
 * caller that cross-checks installing, initiating, and originating
 * package names would otherwise observe an inconsistency between
 * spoofed and unspoofed values. The three getters are hooked at the
 * method level, which Frida applies to every instance of the class
 * regardless of where or how that instance was constructed; hooking
 * PackageManager.getInstallSourceInfo() itself is therefore not
 * required for the spoofed values to take effect on its return object.
 *
 * Gated by installerSpoofEnabled — see the module-level flag
 * declaration and its override in init().
 *
 * References:
 *   https://developer.android.com/reference/android/content/pm/PackageManager#getInstallerPackageName(java.lang.String)
 *   https://developer.android.com/reference/android/content/pm/PackageManager#getInstallSourceInfo(java.lang.String)
 *   https://developer.android.com/reference/android/content/pm/InstallSourceInfo
 */
function applyInstallerSpoof() {
  const SPOOFED_INSTALLER = "com.android.vending";

  // Deprecated as of API 30. Single overload; explicit signature
  // guards against a future API level introducing an additional one.
  try {
    var APM = Java.use("android.app.ApplicationPackageManager");
    const getInstallerTarget = APM.getInstallerPackageName.overload('java.lang.String');
    getInstallerTarget.implementation = function (packageName) {
      return SPOOFED_INSTALLER;
    };
    appliedInstallerHooks.push(getInstallerTarget);
    logI("[+] getInstallerPackageName hooked successfully");
  } catch (err) {
    logW("[!] Failed to hook getInstallerPackageName: " + err);
  }

  // API 30+. Each getter below carries a single, no-argument overload.
  try {
    var ISI = Java.use("android.content.pm.InstallSourceInfo");

    try {
      const installingTarget = ISI.getInstallingPackageName.overload();
      installingTarget.implementation = function () {
        return SPOOFED_INSTALLER;
      };
      appliedInstallerHooks.push(installingTarget);
      logI("[+] InstallSourceInfo.getInstallingPackageName hooked successfully");
    } catch (err) {
      logW("[!] Failed to hook getInstallingPackageName: " + err);
    }

    try {
      const initiatingTarget = ISI.getInitiatingPackageName.overload();
      initiatingTarget.implementation = function () {
        return SPOOFED_INSTALLER;
      };
      appliedInstallerHooks.push(initiatingTarget);
      logI("[+] InstallSourceInfo.getInitiatingPackageName hooked successfully");
    } catch (err) {
      logW("[!] Failed to hook getInitiatingPackageName: " + err);
    }

    try {
      const originatingTarget = ISI.getOriginatingPackageName.overload();
      originatingTarget.implementation = function () {
        return SPOOFED_INSTALLER;
      };
      appliedInstallerHooks.push(originatingTarget);
      logI("[+] InstallSourceInfo.getOriginatingPackageName hooked successfully");
    } catch (err) {
      logW("[!] Failed to hook getOriginatingPackageName: " + err);
    }
  } catch (err) {
    logE("[!] Failed to access class android.content.pm.InstallSourceInfo: " + err);
  }

  logI("[*] Installer identity spoofed as " + SPOOFED_INSTALLER);
}

function revertInstallerSpoof() {
  for (const target of appliedInstallerHooks) {
    try {
      target.implementation = null;
    } catch (err) {
      logW('[!] Failed to revert an installer-spoof hook: ' + err);
    }
  }
  appliedInstallerHooks.length = 0;
  logI('[*] Installer-source spoofing reverted.');
}

/**
 * Bypass for the PairIP license checking mechanism.
 *
 * Hooks `com.pairip.licensecheck.LicenseClient.bindToLicensingService(boolean)`
 * and replaces it with a No-Operation: the original is not called, and no
 * return value is produced (the method's declared return type is void, so
 * no forceReturn is required). The application's flow continues
 * uninterrupted, but it never binds to the PairIP licensing service.
 *
 * Gated by pairipLicenseBypassEnabled — see the module-level flag
 * declaration and its override in init().
 */
function applyPairipLicenseBypass() {
  try {
    const LicenseClient = Java.use('com.pairip.licensecheck.LicenseClient');
    const bindTarget = LicenseClient.bindToLicensingService.overload('boolean');

    bindTarget.implementation = function (flag) {
      logD(`[PairipLicenseCheck] bindToLicensingService(${flag}) NOP-ed`);

      // Intentionally left empty to act as a No-Operation (NOP).
      // We do not call the original method (this.bindToLicensingService(flag))
      // and we do not return anything.
    };
    appliedPairipHooks.push(bindTarget);

    logI('[+] LicenseClient.bindToLicensingService(boolean) NOP-ed');
  } catch (err) {
    logW('[!] Failed to hook LicenseClient.bindToLicensingService: ' + err);
  }
}

function revertPairipLicenseBypass() {
  for (const target of appliedPairipHooks) {
    try {
      target.implementation = null;
    } catch (err) {
      logW('[!] Failed to revert a PairIP hook: ' + err);
    }
  }
  appliedPairipHooks.length = 0;
  logI('[*] PairIP license-check bypass reverted.');
}

/**
 * Fake-installed-package spoofing.
 *
 * Makes configured packages appear installed to the target app, even
 * though they aren't actually present on the device. Covers both the
 * direct-lookup surface (return a fabricated PackageInfo/ApplicationInfo
 * for the requested name) and the enumeration surface (append the
 * fabricated entries to the returned list).
 *
 *   - PackageManager.getPackageInfo(String, int)
 *   - PackageManager.getPackageInfo(String, PackageInfoFlags)          [API 33+]
 *   - PackageManager.getApplicationInfo(String, int)
 *   - PackageManager.getApplicationInfo(String, ApplicationInfoFlags)  [API 33+]
 *   - PackageManager.getInstalledPackages(int)
 *   - PackageManager.getInstalledPackages(long, int)                  [API 33+]
 *   - PackageManager.getInstalledPackages(PackageInfoFlags)           [API 33+]
 *   - PackageManager.getInstalledApplications(int)
 *   - PackageManager.getInstalledApplications(long, int)              [API 33+]
 *   - PackageManager.getInstalledApplications(ApplicationInfoFlags)   [API 33+]
 *
 * Fabricated objects carry plausible field values so common checks pass:
 * versionCode/versionName are set on PackageInfo, and ApplicationInfo
 * gets a uid in the user-app range (10000+), an install path under
 * /data/app/, and the FLAG_INSTALLED bit. FLAG_SYSTEM is set only if the
 * per-package config declares isSystem: "true".
 *
 * Enumeration: the real result list is iterated once to detect which
 * fabricated package names are already present (defensive — this can
 * happen if the test device actually has one of the configured packages
 * installed, or if the hook fires twice), then only the missing ones are
 * appended. The list is rebuilt as a fresh ArrayList rather than mutated
 * in place, since some PackageManager paths return unmodifiable lists.
 * ParceledListSlice wrapping is preserved when present.
 *
 * resolveActivity() and queryIntentActivities() are NOT augmented — a
 * fabricated package has no real activities, and constructing a valid
 * ResolveInfo/ActivityInfo chain with a plausible componentName is
 * substantially more involved than a PackageInfo/ApplicationInfo
 * construction. A caller enumerating launchable activities will not
 * observe fabricated entries; direct presence checks will.
 *
 * The suspiciousPackageSpoofEnabled module filters packages OUT; this
 * module adds packages IN. Both can be enabled together — a package
 * filtered by one and added by the other would be a configuration
 * mistake, not a supported combination.
 *
 * Gated by installedPackageSpoofEnabled. Values come from
 * installedPackageSpoofValues (see its declaration and resolution in
 * init()).
 *
 * References:
 *   https://developer.android.com/reference/android/content/pm/PackageInfo
 *   https://developer.android.com/reference/android/content/pm/ApplicationInfo
 *   https://developer.android.com/reference/android/content/pm/ApplicationInfo#FLAG_INSTALLED
 *   https://developer.android.com/reference/android/content/pm/ApplicationInfo#FLAG_SYSTEM
 */
function applyInstalledPackageSpoof(pkgMap) {
  const spoofedNames = Object.keys(pkgMap);
  if (spoofedNames.length === 0) {
    logI('[InstalledPackageSpoof] no packages configured — nothing to spoof');
    return;
  }
  const spoofedSet = new Set(spoofedNames);

  // Coerce per-package config to typed values with defaults.
  const configs = {};
  for (const name of spoofedNames) {
    const cfg = pkgMap[name] || {};
    const parsedVersionCode = parseInt(cfg.versionCode, 10);
    const parsedUid = parseInt(cfg.uid, 10);
    configs[name] = {
      versionName: (typeof cfg.versionName === 'string' && cfg.versionName.length > 0) ? cfg.versionName : '1.0.0',
      versionCode: (isNaN(parsedVersionCode) || parsedVersionCode <= 0) ? 1 : parsedVersionCode,
      uid: (isNaN(parsedUid) || parsedUid < 10000) ? 10123 : parsedUid,
      isSystem: cfg.isSystem === 'true' || cfg.isSystem === true
    };
  }

  // Lazy class references — resolved on first use.
  let PackageInfoClass = null;
  let ApplicationInfoClass = null;
  let ArrayListClass = null;

  function ensureClasses() {
    if (PackageInfoClass) return;
    PackageInfoClass = Java.use('android.content.pm.PackageInfo');
    ApplicationInfoClass = Java.use('android.content.pm.ApplicationInfo');
    ArrayListClass = Java.use('java.util.ArrayList');
  }

  function buildFakeApplicationInfo(pkgName) {
    const cfg = configs[pkgName];
    const ai = ApplicationInfoClass.$new();
    ai.packageName.value = pkgName;
    ai.uid.value = cfg.uid;
    // FLAG_SYSTEM = 0x00000001; FLAG_INSTALLED = 0x00800000.
    // FLAG_INSTALLED is set unconditionally — an app that appears in the
    // package list but is missing this bit looks inconsistent to callers
    // that check it.
    const FLAG_SYSTEM = 0x00000001;
    const FLAG_INSTALLED = 0x00800000;
    ai.flags.value = (cfg.isSystem ? FLAG_SYSTEM : 0) | FLAG_INSTALLED;
    // Fields below are string paths the framework itself would populate
    // for an installed package; leaving them null causes some callers to
    // treat the entry as malformed.
    const fakeBase = '/data/app/~~fake/' + pkgName;
    ai.sourceDir.value = fakeBase + '/base.apk';
    ai.publicSourceDir.value = ai.sourceDir.value;
    ai.dataDir.value = '/data/user/0/' + pkgName;
    ai.nativeLibraryDir.value = fakeBase + '/lib/arm64';
    return ai;
  }

  function buildFakePackageInfo(pkgName) {
    const cfg = configs[pkgName];
    const pi = PackageInfoClass.$new();
    pi.packageName.value = pkgName;
    pi.versionName.value = cfg.versionName;
    // versionCode is int (deprecated but still read by legacy code paths).
    // longVersionCode is available on API 28+.
    try { pi.versionCode.value = cfg.versionCode; } catch (e) {}
    try { pi.longVersionCode.value = cfg.versionCode; } catch (e) {}
    // firstInstallTime / lastUpdateTime — plausible, recent timestamps.
    const now = Date.now();
    try { pi.firstInstallTime.value = now; } catch (e) {}
    try { pi.lastUpdateTime.value = now; } catch (e) {}
    pi.applicationInfo.value = buildFakeApplicationInfo(pkgName);
    return pi;
  }

  function resolveClassName(obj) {
    try {
      return obj.getClass().getName();
    } catch (e) {
      try { return obj.class ? obj.class.getName() : '<unknown>'; }
      catch (e2) { return '<unknown>'; }
    }
  }

  /**
   * Rebuilds a PackageInfo/ApplicationInfo list, keeping every real entry
   * and appending a fabricated entry for each configured package that is
   * not already present. Rebuild-as-new-ArrayList avoids relying on the
   * original list being mutable. ParceledListSlice wrapping is preserved.
   */
  function augmentList(originalResult, itemKind) {
    if (!originalResult) return originalResult;

    const className = resolveClassName(originalResult);

    try {
      let originalList = originalResult;
      let wasParceled = false;

      if (className === 'android.content.pm.ParceledListSlice') {
        originalList = originalResult.getList();
        wasParceled = true;
      }

      // Pass 1: copy real entries, note which package names are present.
      //
      // Iterator.next() returns java.lang.Object at the bytecode level
      // (generics are erased at compile time); Frida's property binding
      // reflects that declared type, not the element's runtime class.
      // Each item must therefore be Java.cast() to its real class
      // before reading type-specific fields. Accessing packageName.value
      // on the un-cast Object reference silently throws and would be
      // swallowed by the catch below, leaving the `present` set empty —
      // which in turn would append a fabricated entry for packages that
      // are already installed.
      const rebuilt = ArrayListClass.$new();
      const present = new Set();
      const iterator = originalList.iterator();
      const ItemClass = itemKind === 'PackageInfo' ? PackageInfoClass : ApplicationInfoClass;
      while (iterator.hasNext()) {
        const item = iterator.next();
        rebuilt.add(item);
        try {
          const casted = Java.cast(item, ItemClass);
          const pn = casted.packageName.value;
          if (pn) present.add(pn.toString());
        } catch (e) {
          // Item has no readable packageName — keep it, skip detection.
        }
      }

      // Pass 2: append fakes not already present.
      let appended = 0;
      for (const pkgName of spoofedNames) {
        if (present.has(pkgName)) continue;
        rebuilt.add(itemKind === 'PackageInfo'
          ? buildFakePackageInfo(pkgName)
          : buildFakeApplicationInfo(pkgName));
        appended++;
      }

      if (appended > 0) {
        logD(`[InstalledPackageSpoof] appended ${appended} fake ${itemKind} entries (class=${className})`);
      }

      if (wasParceled) {
        const ParceledListSlice = Java.use('android.content.pm.ParceledListSlice');
        return ParceledListSlice.$new(rebuilt);
      }
      return rebuilt;
    } catch (e) {
      logW(`[InstalledPackageSpoof] list augmentation failed (class=${className}): ${e.message}`);
      return originalResult;
    }
  }

  try {
    ensureClasses();
    const APM = Java.use('android.app.ApplicationPackageManager');

    // ---- Direct lookups: PackageInfo ----
    try {
      const getPkgInfoIntTarget = APM.getPackageInfo.overload('java.lang.String', 'int');
      getPkgInfoIntTarget.implementation = function (pkgName, flags) {
        try {
          if (spoofedSet.has(pkgName)) {
            logD(`[InstalledPackageSpoof] getPackageInfo(${pkgName}, int) -> fake`);
            return buildFakePackageInfo(pkgName);
          }
        } catch (buildErr) {
          logW(`[InstalledPackageSpoof] getPackageInfo(int) fake build failed for ${pkgName}: ${buildErr}`);
        }
        return this.getPackageInfo(pkgName, flags);
      };
      appliedInstalledPackageHooks.push(getPkgInfoIntTarget);
      logI('[+] getPackageInfo(String, int) spoofed');
    } catch (e) { logW('[!] getPackageInfo(String, int) hook failed: ' + e); }

    try {
      const getPkgInfoFlagsTarget = APM.getPackageInfo.overload('java.lang.String', 'android.content.pm.PackageManager$PackageInfoFlags');
      getPkgInfoFlagsTarget.implementation = function (pkgName, flags) {
        try {
          if (spoofedSet.has(pkgName)) {
            logD(`[InstalledPackageSpoof] getPackageInfo(${pkgName}, flags) -> fake`);
            return buildFakePackageInfo(pkgName);
          }
        } catch (buildErr) {
          logW(`[InstalledPackageSpoof] getPackageInfo(flags) fake build failed for ${pkgName}: ${buildErr}`);
        }
        return this.getPackageInfo(pkgName, flags);
      };
      appliedInstalledPackageHooks.push(getPkgInfoFlagsTarget);
      logI('[+] getPackageInfo(String, PackageInfoFlags) spoofed');
    } catch (e) { logW('[!] getPackageInfo(String, PackageInfoFlags) hook failed (expected on API < 33): ' + e); }

    // ---- Direct lookups: ApplicationInfo ----
    try {
      const getAppInfoIntTarget = APM.getApplicationInfo.overload('java.lang.String', 'int');
      getAppInfoIntTarget.implementation = function (pkgName, flags) {
        try {
          if (spoofedSet.has(pkgName)) {
            logD(`[InstalledPackageSpoof] getApplicationInfo(${pkgName}, int) -> fake`);
            return buildFakeApplicationInfo(pkgName);
          }
        } catch (buildErr) {
          logW(`[InstalledPackageSpoof] getApplicationInfo(int) fake build failed for ${pkgName}: ${buildErr}`);
        }
        return this.getApplicationInfo(pkgName, flags);
      };
      appliedInstalledPackageHooks.push(getAppInfoIntTarget);
      logI('[+] getApplicationInfo(String, int) spoofed');
    } catch (e) { logW('[!] getApplicationInfo(String, int) hook failed: ' + e); }

    try {
      const getAppInfoFlagsTarget = APM.getApplicationInfo.overload('java.lang.String', 'android.content.pm.PackageManager$ApplicationInfoFlags');
      getAppInfoFlagsTarget.implementation = function (pkgName, flags) {
        try {
          if (spoofedSet.has(pkgName)) {
            logD(`[InstalledPackageSpoof] getApplicationInfo(${pkgName}, flags) -> fake`);
            return buildFakeApplicationInfo(pkgName);
          }
        } catch (buildErr) {
          logW(`[InstalledPackageSpoof] getApplicationInfo(flags) fake build failed for ${pkgName}: ${buildErr}`);
        }
        return this.getApplicationInfo(pkgName, flags);
      };
      appliedInstalledPackageHooks.push(getAppInfoFlagsTarget);
      logI('[+] getApplicationInfo(String, ApplicationInfoFlags) spoofed');
    } catch (e) { logW('[!] getApplicationInfo(String, ApplicationInfoFlags) hook failed (expected on API < 33): ' + e); }

    // ---- Enumeration: getInstalledPackages ----
    try {
      const getInstalledPkgsIntTarget = APM.getInstalledPackages.overload('int');
      getInstalledPkgsIntTarget.implementation = function (flags) {
        return augmentList(this.getInstalledPackages(flags), 'PackageInfo');
      };
      appliedInstalledPackageHooks.push(getInstalledPkgsIntTarget);
      logI('[+] getInstalledPackages(int) augmented');
    } catch (e) { logW('[!] getInstalledPackages(int) hook failed: ' + e); }

    try {
      const getInstalledPkgsLongIntTarget = APM.getInstalledPackages.overload('long', 'int');
      getInstalledPkgsLongIntTarget.implementation = function (flags, userId) {
        return augmentList(this.getInstalledPackages(flags, userId), 'PackageInfo');
      };
      appliedInstalledPackageHooks.push(getInstalledPkgsLongIntTarget);
      logI('[+] getInstalledPackages(long, int) augmented');
    } catch (e) { logW('[!] getInstalledPackages(long, int) hook failed (expected on API < 33): ' + e); }

    try {
      const getInstalledPkgsFlagsTarget = APM.getInstalledPackages.overload('android.content.pm.PackageManager$PackageInfoFlags');
      getInstalledPkgsFlagsTarget.implementation = function (flags) {
        return augmentList(this.getInstalledPackages(flags), 'PackageInfo');
      };
      appliedInstalledPackageHooks.push(getInstalledPkgsFlagsTarget);
      logI('[+] getInstalledPackages(PackageInfoFlags) augmented');
    } catch (e) { logW('[!] getInstalledPackages(PackageInfoFlags) hook failed (expected on API < 33): ' + e); }

    // ---- Enumeration: getInstalledApplications ----
    try {
      const getInstalledAppsIntTarget = APM.getInstalledApplications.overload('int');
      getInstalledAppsIntTarget.implementation = function (flags) {
        return augmentList(this.getInstalledApplications(flags), 'ApplicationInfo');
      };
      appliedInstalledPackageHooks.push(getInstalledAppsIntTarget);
      logI('[+] getInstalledApplications(int) augmented');
    } catch (e) { logW('[!] getInstalledApplications(int) hook failed: ' + e); }

    try {
      const getInstalledAppsLongIntTarget = APM.getInstalledApplications.overload('long', 'int');
      getInstalledAppsLongIntTarget.implementation = function (flags, userId) {
        return augmentList(this.getInstalledApplications(flags, userId), 'ApplicationInfo');
      };
      appliedInstalledPackageHooks.push(getInstalledAppsLongIntTarget);
      logI('[+] getInstalledApplications(long, int) augmented');
    } catch (e) { logW('[!] getInstalledApplications(long, int) hook failed (expected on API < 33): ' + e); }

    try {
      const getInstalledAppsFlagsTarget = APM.getInstalledApplications.overload('android.content.pm.PackageManager$ApplicationInfoFlags');
      getInstalledAppsFlagsTarget.implementation = function (flags) {
        return augmentList(this.getInstalledApplications(flags), 'ApplicationInfo');
      };
      appliedInstalledPackageHooks.push(getInstalledAppsFlagsTarget);
      logI('[+] getInstalledApplications(ApplicationInfoFlags) augmented');
    } catch (e) { logW('[!] getInstalledApplications(ApplicationInfoFlags) hook failed (expected on API < 33): ' + e); }

    logI(`[*] Installed-package spoofing active for ${spoofedNames.length} package(s).`);
  } catch (err) {
    logE('[!] Failed to set up installed-package spoof hooks: ' + err);
  }
}

function revertInstalledPackageSpoof() {
  for (const target of appliedInstalledPackageHooks) {
    try {
      target.implementation = null;
    } catch (err) {
      logW('[!] Failed to revert a fake-installed-package hook: ' + err);
    }
  }
  appliedInstalledPackageHooks.length = 0;
  logI('[*] Fake-installed-package spoofing reverted.');
}

/**
 * FLAG_SECURE screenshot / screen-recording restriction bypass.
 *
 * Strips WindowManager.LayoutParams.FLAG_SECURE (0x2000) from window
 * flags before they take effect, and disables SurfaceView's
 * independent secure layer, across:
 *
 *   - Window.setFlags(int, int)
 *   - Window.addFlags(int)
 *   - Window.setAttributes(WindowManager.LayoutParams)
 *   - SurfaceView.setSecure(boolean)
 *   - WindowManagerImpl.addView(View, ViewGroup.LayoutParams)
 *   - WindowManagerImpl.updateViewLayout(View, ViewGroup.LayoutParams)
 *
 * The WindowManagerImpl entry points cover views attached directly to
 * the system WindowManager rather than through an Activity's own
 * Window — a pattern used by overlay-rendered secure content such as
 * DRM playback surfaces or floating PIN-entry views, which would
 * otherwise bypass the Window-scoped hooks above.
 *
 * Gated by flagSecureBypassEnabled — see the module-level flag
 * declaration and its override in init().
 *
 * References:
 *   https://developer.android.com/reference/android/view/Window#setFlags(int,%20int)
 *   https://developer.android.com/reference/android/view/Window#addFlags(int)
 *   https://developer.android.com/reference/android/view/Window#setAttributes(android.view.WindowManager.LayoutParams)
 *   https://developer.android.com/reference/android/view/SurfaceView#setSecure(boolean)
 *   https://developer.android.com/reference/android/view/WindowManager#addView(android.view.View,%20android.view.ViewGroup.LayoutParams)
 *   https://developer.android.com/reference/android/view/WindowManager#updateViewLayout(android.view.View,%20android.view.ViewGroup.LayoutParams)
 */
function applyFlagSecureBypass() {
  const FLAG_SECURE = 0x2000;

  // Each hook below specifies its overload explicitly, guarding
  // against a future API level introducing an additional signature.

  try {
    var Window = Java.use("android.view.Window");
    var originalSetFlags = Window.setFlags.overload('int', 'int');
    var setFlagsTarget = Window.setFlags.overload('int', 'int');
    setFlagsTarget.implementation = function (flags, mask) {
      // setFlags(flags, mask) semantics: attrs.flags = (attrs.flags & ~mask)
      // | (flags & mask) — only the bits set in `mask` are ever touched.
      // Stripping FLAG_SECURE from `mask` (as a prior version of this hook
      // did) would make this call unable to ever touch that bit at all,
      // including clearing it if it was already set by some other path
      // (theme default, a call made before this hook installed). Stripping
      // it from `flags` only, with `mask` left intact, means: if the caller
      // targets FLAG_SECURE via `mask`, the real implementation force-clears
      // it regardless of prior state (the intended behavior); if the caller
      // doesn't target it, this is a no-op either way. Safe in both cases.
      return originalSetFlags.call(this, flags & ~FLAG_SECURE, mask);
    };
    appliedFlagSecureHooks.push(setFlagsTarget);
    logI("[+] Window.setFlags hooked");
  } catch (e) {
    logW("[!] Window.setFlags hook failed: " + e);
  }

  try {
    var Window2 = Java.use("android.view.Window");
    var originalAddFlags = Window2.addFlags.overload('int');
    var addFlagsTarget = Window2.addFlags.overload('int');
    addFlagsTarget.implementation = function (flags) {
      return originalAddFlags.call(this, flags & ~FLAG_SECURE);
    };
    appliedFlagSecureHooks.push(addFlagsTarget);
    logI("[+] Window.addFlags hooked");
  } catch (e) {
    logW("[!] Window.addFlags hook failed: " + e);
  }

  try {
    var Window3 = Java.use("android.view.Window");
    var originalSetAttrs = Window3.setAttributes.overload('android.view.WindowManager$LayoutParams');
    var setAttrsTarget = Window3.setAttributes.overload('android.view.WindowManager$LayoutParams');
    setAttrsTarget.implementation = function (attrs) {
      try {
        if (attrs != null) {
          attrs.flags.value = attrs.flags.value & ~FLAG_SECURE;
        }
      } catch (innerErr) {
        logW("[!] Window.setAttributes flag strip failed: " + innerErr);
      }
      return originalSetAttrs.call(this, attrs);
    };
    appliedFlagSecureHooks.push(setAttrsTarget);
    logI("[+] Window.setAttributes hooked");
  } catch (e) {
    logW("[!] Window.setAttributes hook failed: " + e);
  }

  try {
    var SurfaceView = Java.use("android.view.SurfaceView");
    var originalSetSecure = SurfaceView.setSecure.overload('boolean');
    var setSecureTarget = SurfaceView.setSecure.overload('boolean');
    setSecureTarget.implementation = function (isSecure) {
      return originalSetSecure.call(this, false);
    };
    appliedFlagSecureHooks.push(setSecureTarget);
    logI("[+] SurfaceView.setSecure hooked");
  } catch (e) {
    logW("[!] SurfaceView.setSecure hook failed: " + e);
  }

  // Strips FLAG_SECURE from the LayoutParams supplied when a view is
  // attached directly to the system WindowManager, independent of any
  // Activity Window. The parameter's declared type is
  // ViewGroup.LayoutParams; a runtime cast to WindowManager.LayoutParams
  // is required to access the flags field, and is skipped for callers
  // that pass a LayoutParams instance without that field.
  try {
    var WindowManagerImpl = Java.use("android.view.WindowManagerImpl");
    var WMLayoutParams = Java.use("android.view.WindowManager$LayoutParams");

    var originalAddView = WindowManagerImpl.addView.overload('android.view.View', 'android.view.ViewGroup$LayoutParams');
    var addViewTarget = WindowManagerImpl.addView.overload('android.view.View', 'android.view.ViewGroup$LayoutParams');
    addViewTarget.implementation = function (view, params) {
      try {
        if (params != null) {
          const casted = Java.cast(params, WMLayoutParams);
          casted.flags.value = casted.flags.value & ~FLAG_SECURE;
        }
      } catch (castErr) {
        // params is not a WindowManager.LayoutParams instance; nothing to strip.
      }
      return originalAddView.call(this, view, params);
    };
    appliedFlagSecureHooks.push(addViewTarget);
    logI("[+] WindowManagerImpl.addView hooked");
  } catch (e) {
    logW("[!] WindowManagerImpl.addView hook failed: " + e);
  }

  try {
    var WindowManagerImpl2 = Java.use("android.view.WindowManagerImpl");
    var WMLayoutParams2 = Java.use("android.view.WindowManager$LayoutParams");

    var originalUpdateViewLayout = WindowManagerImpl2.updateViewLayout.overload('android.view.View', 'android.view.ViewGroup$LayoutParams');
    var updateViewLayoutTarget = WindowManagerImpl2.updateViewLayout.overload('android.view.View', 'android.view.ViewGroup$LayoutParams');
    updateViewLayoutTarget.implementation = function (view, params) {
      try {
        if (params != null) {
          const casted = Java.cast(params, WMLayoutParams2);
          casted.flags.value = casted.flags.value & ~FLAG_SECURE;
        }
      } catch (castErr) {
        // params is not a WindowManager.LayoutParams instance; nothing to strip.
      }
      return originalUpdateViewLayout.call(this, view, params);
    };
    appliedFlagSecureHooks.push(updateViewLayoutTarget);
    logI("[+] WindowManagerImpl.updateViewLayout hooked");
  } catch (e) {
    logW("[!] WindowManagerImpl.updateViewLayout hook failed: " + e);
  }
}

function revertFlagSecureBypass() {
  for (const target of appliedFlagSecureHooks) {
    try {
      target.implementation = null;
    } catch (err) {
      logW('[!] Failed to revert a FLAG_SECURE hook: ' + err);
    }
  }
  appliedFlagSecureHooks.length = 0;
  logI('[*] FLAG_SECURE bypass reverted.');
}

/**
 * VPN/proxy detection bypass.
 *
 * Hides active VPN and configured proxy state from every standard
 * Android/Java detection surface:
 *
 *   Network identity:
 *     - NetworkInterface.getName()                         [tun/ppp/tap -> "wlan0"]
 *     - NetworkCapabilities.hasTransport(int)              [TRANSPORT_VPN -> false]
 *     - NetworkCapabilities.hasCapability(int)             [NET_CAPABILITY_NOT_VPN -> true]
 *     - NetworkCapabilities.getTransportTypes()            [TRANSPORT_VPN filtered out]
 *     - NetworkInfo.getType()                              [TYPE_VPN -> TYPE_MOBILE]
 *     - NetworkInfo.getTypeName()                          ["VPN" -> "MOBILE"]
 *     - ConnectivityManager.getActiveNetworkInfo()         [VPN network -> null]
 *
 *   JVM proxy selection:
 *     - java.net.ProxySelector.getDefault().select(URI)    [-> [NO_PROXY]]
 *       Hooked on the concrete class returned by getDefault(), not by
 *       subclassing the abstract java.net.ProxySelector. Subclassing
 *       under Gadget has been observed to fail silently — the
 *       registered subclass can be released by the bridge and return
 *       null to the caller, causing a NullPointerException on the
 *       subsequent ProxySelector.select() call.
 *
 *   Android proxy APIs (current):
 *     - ConnectivityManager.getDefaultProxy()              [-> null]
 *     - ConnectivityManager.getProxyForNetwork(Network)    [-> null]
 *     - ConnectivityManager.getGlobalProxy()               [-> null]
 *     - LinkProperties.getHttpProxy()                      [-> null]
 *
 *   Android proxy APIs (legacy, deprecated but still in use):
 *     - android.net.Proxy.getHost(Context)                 [-> null]
 *     - android.net.Proxy.getPort(Context)                 [-> -1]
 *     - android.net.Proxy.getDefaultHost()                 [-> null]
 *     - android.net.Proxy.getDefaultPort()                 [-> -1]
 *     - android.net.Proxy.getProxy(Context, String)        [-> Proxy.NO_PROXY]
 *
 *   ProxyInfo object surface (defense-in-depth):
 *     - ProxyInfo.getHost()                                [-> null]
 *     - ProxyInfo.getPort()                                [-> -1]
 *     - ProxyInfo.getPacFileUrl()                          [-> null]
 *     - ProxyInfo.getSocketAddress()                       [-> null]
 *     - ProxyInfo.makeProxy()                              [-> Proxy.NO_PROXY]
 *     - ProxyInfo.toString()                               [-> "DIRECT"]
 *     - ProxyInfo.isPacProxy()                             [-> false]
 *     - ProxyInfo.isValid()                                [-> false]
 *       Every ProxyInfo reader is covered even if the object arrived
 *       through a path not intercepted above (cached before init,
 *       obtained via WifiConfiguration, constructed by reflection).
 *
 *   JVM proxy properties:
 *     - System.getProperty(String)                         [VPN/proxy keys -> null]
 *     - System.getProperty(String, String)                 [VPN/proxy keys -> null]
 *
 * Design notes:
 *   - LinkProperties.getHttpProxy() is hooked rather than
 *     ConnectivityManager.getLinkProperties(Network). getLinkProperties
 *     returns a full LinkProperties object — interface name, routes,
 *     DNS, MTU — that legitimate callers depend on. Returning a
 *     fabricated object would strip that data and break unrelated app
 *     behavior. Hooking the single proxy getter leaves the real
 *     LinkProperties intact for every non-proxy use.
 *   - ProxyInfo.toString() returns "DIRECT" rather than a fabricated
 *     "ProxyInfo{...}" string. "DIRECT" is the string form of
 *     java.net.Proxy.NO_PROXY, matching the shape a caller observes
 *     when no proxy is configured. A caller checking
 *     toString().contains(":") gets false.
 *   - ProxyInfo.makeProxy() and android.net.Proxy.getProxy() return
 *     java.net.Proxy.NO_PROXY directly rather than attempting to build
 *     a Proxy from now-null host/port fields.
 *
 * Gated by vpnProxyBypassEnabled — see the module-level flag
 * declaration and its override in init().
 *
 * References:
 *   https://developer.android.com/reference/java/net/NetworkInterface#getName()
 *   https://developer.android.com/reference/java/net/ProxySelector
 *   https://developer.android.com/reference/java/lang/System#getProperty(java.lang.String)
 *   https://developer.android.com/reference/android/net/ConnectivityManager#getDefaultProxy()
 *   https://developer.android.com/reference/android/net/ConnectivityManager#getProxyForNetwork(android.net.Network)
 *   https://developer.android.com/reference/android/net/ConnectivityManager#getGlobalProxy()
 *   https://developer.android.com/reference/android/net/LinkProperties#getHttpProxy()
 *   https://developer.android.com/reference/android/net/ProxyInfo
 *   https://developer.android.com/reference/android/net/NetworkCapabilities#hasTransport(int)
 *   https://developer.android.com/reference/android/net/NetworkCapabilities#hasCapability(int)
 *   https://developer.android.com/reference/android/net/NetworkCapabilities#getTransportTypes()
 *   https://developer.android.com/reference/android/net/NetworkCapabilities#TRANSPORT_VPN
 *   https://developer.android.com/reference/android/net/NetworkCapabilities#NET_CAPABILITY_NOT_VPN
 *   https://developer.android.com/reference/android/net/NetworkInfo#getType()
 *   https://developer.android.com/reference/android/net/NetworkInfo#getTypeName()
 *   https://developer.android.com/reference/android/net/ConnectivityManager#getActiveNetworkInfo()
 *   https://developer.android.com/reference/android/net/Proxy#getHost(android.content.Context)
 *   https://developer.android.com/reference/android/net/Proxy#getPort(android.content.Context)
 *   https://developer.android.com/reference/android/net/Proxy#getDefaultHost()
 *   https://developer.android.com/reference/android/net/Proxy#getDefaultPort()
 *   https://developer.android.com/reference/android/net/Proxy#getProxy(android.content.Context,%20java.lang.String)
 */
function applyVpnProxyDetectionBypass() {
  const TRANSPORT_VPN = 4;
  const NET_CAPABILITY_NOT_VPN = 15;
  const TYPE_VPN = 17;
  const TYPE_MOBILE = 0;

  try {
    var NetworkInterface = Java.use("java.net.NetworkInterface");
    var getNameTarget = NetworkInterface.getName.overload();
    getNameTarget.implementation = function () {
      var name = this.getName();
      if (name !== null && typeof name === "string") {
        if (name.indexOf("tun") !== -1 || name.indexOf("ppp") !== -1 || name.indexOf("tap") !== -1) {
          return "wlan0";
        }
      }
      return name;
    };
    appliedVpnProxyHooks.push(getNameTarget);
    logI("[+] NetworkInterface.getName hooked");
  } catch (err) {
    logW("[!] Failed to hook NetworkInterface.getName: " + err);
  }

  function isSensitiveKey(key) {
    if (key === null) return false;
    var lk = key.toLowerCase();
    if (lk.indexOf("vpn") !== -1) return true;
    if (lk.indexOf("proxyhost") !== -1 || lk.indexOf("proxyport") !== -1 || lk.indexOf("proxyname") !== -1) return true;
    if (key === "socksProxyVersion" || key === "java.net.useSystemProxies") return true;
    return false;
  }

  try {
    var System1 = Java.use("java.lang.System");
    var getPropertyTarget = System1.getProperty.overload('java.lang.String');
    getPropertyTarget.implementation = function (key) {
      if (isSensitiveKey(key)) return null;
      return this.getProperty(key);
    };
    appliedVpnProxyHooks.push(getPropertyTarget);
    logI("[+] System.getProperty(String) hooked");
  } catch (err) {
    logW("[!] Failed to hook System.getProperty(String): " + err);
  }

  try {
    var System2 = Java.use("java.lang.System");
    var getPropertyDefTarget = System2.getProperty.overload('java.lang.String', 'java.lang.String');
    getPropertyDefTarget.implementation = function (key, def) {
      if (isSensitiveKey(key)) return null;
      return this.getProperty(key, def);
    };
    appliedVpnProxyHooks.push(getPropertyDefTarget);
    logI("[+] System.getProperty(String, String) hooked");
  } catch (err) {
    logW("[!] Failed to hook System.getProperty(String, String): " + err);
  }

  try {
    var NetworkCapabilities1 = Java.use("android.net.NetworkCapabilities");
    var hasTransportTarget = NetworkCapabilities1.hasTransport.overload('int');
    hasTransportTarget.implementation = function (transportType) {
      if (transportType === TRANSPORT_VPN) return false;
      return this.hasTransport(transportType);
    };
    appliedVpnProxyHooks.push(hasTransportTarget);
    logI("[+] NetworkCapabilities.hasTransport hooked");
  } catch (err) {
    logW("[!] Failed to hook NetworkCapabilities.hasTransport: " + err);
  }

  try {
    var NetworkCapabilities2 = Java.use("android.net.NetworkCapabilities");
    var hasCapabilityTarget = NetworkCapabilities2.hasCapability.overload('int');
    hasCapabilityTarget.implementation = function (capability) {
      if (capability === NET_CAPABILITY_NOT_VPN) return true;
      return this.hasCapability(capability);
    };
    appliedVpnProxyHooks.push(hasCapabilityTarget);
    logI("[+] NetworkCapabilities.hasCapability hooked");
  } catch (err) {
    logW("[!] Failed to hook NetworkCapabilities.hasCapability: " + err);
  }

  try {
    var NetworkCapabilities3 = Java.use("android.net.NetworkCapabilities");
    var getTransportTypesTarget = NetworkCapabilities3.getTransportTypes.overload();
    getTransportTypesTarget.implementation = function () {
      var types = this.getTransportTypes();
      if (types === null) return null;
      var filtered = [];
      for (var i = 0; i < types.length; i++) {
        if (types[i] !== TRANSPORT_VPN) {
          filtered.push(types[i]);
        }
      }
      // Explicit conversion back to a Java int[]: the declared return
      // type is int[], and a plain JS array should not be relied on
      // to auto-marshal correctly as one.
      return Java.array('int', filtered);
    };
    appliedVpnProxyHooks.push(getTransportTypesTarget);
    logI("[+] NetworkCapabilities.getTransportTypes hooked");
  } catch (err) {
    logW("[!] Failed to hook NetworkCapabilities.getTransportTypes: " + err);
  }

  try {
    var NetworkInfo1 = Java.use("android.net.NetworkInfo");
    var getTypeTarget = NetworkInfo1.getType.overload();
    getTypeTarget.implementation = function () {
      var type = this.getType();
      if (type === TYPE_VPN) return TYPE_MOBILE;
      return type;
    };
    appliedVpnProxyHooks.push(getTypeTarget);
    logI("[+] NetworkInfo.getType hooked");
  } catch (err) {
    logW("[!] Failed to hook NetworkInfo.getType: " + err);
  }

  try {
    var NetworkInfo2 = Java.use("android.net.NetworkInfo");
    var getTypeNameTarget = NetworkInfo2.getTypeName.overload();
    getTypeNameTarget.implementation = function () {
      var name = this.getTypeName();
      if (name !== null && typeof name === "string" && name.toUpperCase() === "VPN") return "MOBILE";
      return name;
    };
    appliedVpnProxyHooks.push(getTypeNameTarget);
    logI("[+] NetworkInfo.getTypeName hooked");
  } catch (err) {
    logW("[!] Failed to hook NetworkInfo.getTypeName: " + err);
  }

  try {
    var CM = Java.use("android.net.ConnectivityManager");
    var getActiveNetworkInfoTarget = CM.getActiveNetworkInfo.overload();
    getActiveNetworkInfoTarget.implementation = function () {
      var info = this.getActiveNetworkInfo();
      if (info !== null && info.getType() === TYPE_VPN) return null;
      return info;
    };
    appliedVpnProxyHooks.push(getActiveNetworkInfoTarget);
    logI("[+] ConnectivityManager.getActiveNetworkInfo hooked");
  } catch (err) {
    logW("[!] Failed to hook ConnectivityManager.getActiveNetworkInfo: " + err);
  }

  try {
    var Proxy1 = Java.use("android.net.Proxy");
    var getHostTarget = Proxy1.getHost.overload('android.content.Context');
    getHostTarget.implementation = function (ctx) {
      return null;
    };
    appliedVpnProxyHooks.push(getHostTarget);
    logI("[+] Proxy.getHost hooked");
  } catch (err) {
    logW("[!] Failed to hook Proxy.getHost: " + err);
  }

  try {
    var Proxy2 = Java.use("android.net.Proxy");
    var getPortTarget = Proxy2.getPort.overload('android.content.Context');
    getPortTarget.implementation = function (ctx) {
      return -1;
    };
    appliedVpnProxyHooks.push(getPortTarget);
    logI("[+] Proxy.getPort hooked");
  } catch (err) {
    logW("[!] Failed to hook Proxy.getPort: " + err);
  }

  try {
    var Proxy3 = Java.use("android.net.Proxy");
    var getDefaultHostTarget = Proxy3.getDefaultHost.overload();
    getDefaultHostTarget.implementation = function () {
      return null;
    };
    appliedVpnProxyHooks.push(getDefaultHostTarget);
    logI("[+] Proxy.getDefaultHost hooked");
  } catch (err) {
    logW("[!] Failed to hook Proxy.getDefaultHost: " + err);
  }

  try {
    var Proxy4 = Java.use("android.net.Proxy");
    var getDefaultPortTarget = Proxy4.getDefaultPort.overload();
    getDefaultPortTarget.implementation = function () {
      return -1;
    };
    appliedVpnProxyHooks.push(getDefaultPortTarget);
    logI("[+] Proxy.getDefaultPort hooked");
  } catch (err) {
    logW("[!] Failed to hook Proxy.getDefaultPort: " + err);
  }
  // java.net.ProxySelector is the JVM-wide proxy selection mechanism,
  // distinct from the deprecated android.net.Proxy accessors hooked
  // above. Modern apps commonly call
  //   ProxySelector.getDefault().select(URI)
  // to enumerate applicable proxies for a URL. On Android this path
  // reads proxy config from ConnectivityManager / system network state
  // rather than through android.net.Proxy, so the hooks above do not
  // cover it.
  //
  // Implementation note: rather than subclassing the abstract
  // java.net.ProxySelector and replacing getDefault() — which is
  // unreliable under Gadget because the registered subclass can be
  // silently released by the bridge and return null to the caller —
  // this hook targets the select(URI) method on whichever concrete
  // class the platform returns from getDefault(). No subclassing, no
  // cached singleton, no GC hazard.
  try {
    const ProxySelectorClass = Java.use('java.net.ProxySelector');
    const ProxyClass = Java.use('java.net.Proxy');
    const ArrayListClass = Java.use('java.util.ArrayList');
  
    // Probe the current default. This runs before any hook on
    // ProxySelector is installed, so it sees the platform's original.
    const defaultSelector = ProxySelectorClass.getDefault();
    if (defaultSelector === null) {
      logW('[!] ProxySelector.getDefault() returned null — cannot determine concrete class');
    } else {
      const concreteClassName = defaultSelector.$className;
      logI(`[*] ProxySelector concrete class: ${concreteClassName}`);
  
      const ConcreteClass = Java.use(concreteClassName);
      const selectTarget = ConcreteClass.select.overload('java.net.URI');
      selectTarget.implementation = function (uri) {
        try {
          const list = ArrayListClass.$new();
          list.add(ProxyClass.NO_PROXY.value);
          return list;
        } catch (innerErr) {
          logW(`[!] NoProxy select() failed: ${innerErr}`);
          return this.select(uri);
        }
      };
      appliedVpnProxyHooks.push(selectTarget);
      logI(`[+] ${concreteClassName}.select(URI) hooked — returns NO_PROXY`);
    }
  } catch (err) {
    logW('[!] Failed to hook ProxySelector: ' + err);
  }
  // ------------------------------------------------------------------
  // ConnectivityManager — current documented proxy-query APIs
  // ------------------------------------------------------------------
  // getDefaultProxy() returns the per-process proxy; getGlobalProxy()
  // returns the device-wide proxy set by device admin / MDM. Both are
  // independent of the deprecated android.net.Proxy accessors and the
  // JVM-level ProxySelector path.
  try {
    const CMForProxy = Java.use('android.net.ConnectivityManager');
  
    try {
      const getDefaultProxyTarget = CMForProxy.getDefaultProxy.overload();
      getDefaultProxyTarget.implementation = function () {
        return null;
      };
      appliedVpnProxyHooks.push(getDefaultProxyTarget);
      logI('[+] ConnectivityManager.getDefaultProxy hooked');
    } catch (err) {
      logW('[!] ConnectivityManager.getDefaultProxy hook failed (expected on API < 23): ' + err);
    }

    try {
      const getProxyForNetworkTarget = CMForProxy.getProxyForNetwork.overload('android.net.Network');
      getProxyForNetworkTarget.implementation = function (network) {
        return null;
      };
      appliedVpnProxyHooks.push(getProxyForNetworkTarget);
      logI('[+] ConnectivityManager.getProxyForNetwork(Network) hooked');
    } catch (err) {
      logW('[!] ConnectivityManager.getProxyForNetwork(Network) hook failed (expected on API < 23): ' + err);
    }

    try {
      const getGlobalProxyTarget = CMForProxy.getGlobalProxy.overload();
      getGlobalProxyTarget.implementation = function () {
        return null;
      };
      appliedVpnProxyHooks.push(getGlobalProxyTarget);
      logI('[+] ConnectivityManager.getGlobalProxy hooked');
    } catch (err) {
      logW('[!] ConnectivityManager.getGlobalProxy hook failed: ' + err);
    }
  } catch (err) {
    logE('[!] Failed to access android.net.ConnectivityManager for proxy hooks: ' + err);
  }
  
  // ------------------------------------------------------------------
  // LinkProperties — the recommended proxy getter
  // ------------------------------------------------------------------
  // Hooked rather than ConnectivityManager.getLinkProperties(Network),
  // which returns a full LinkProperties object (interface name, routes,
  // DNS, MTU) that legitimate callers depend on.
  try {
    const LPClass = Java.use('android.net.LinkProperties');
    const getHttpProxyTarget = LPClass.getHttpProxy.overload();
    getHttpProxyTarget.implementation = function () {
      return null;
    };
    appliedVpnProxyHooks.push(getHttpProxyTarget);
    logI('[+] LinkProperties.getHttpProxy hooked');
  } catch (err) {
    logW('[!] LinkProperties.getHttpProxy hook failed: ' + err);
  }
  
  // ------------------------------------------------------------------
  // ProxyInfo — object-level defense in depth
  // ------------------------------------------------------------------
  // Every field-level read is covered so that a ProxyInfo instance that
  // reaches the app through a path not intercepted above (cached before
  // init, obtained via WifiConfiguration, constructed by reflection)
  // still reads as a DIRECT connection.
  try {
    const PIClass = Java.use('android.net.ProxyInfo');
    const JProxyClass = Java.use('java.net.Proxy');
  
    try {
      const piGetHostTarget = PIClass.getHost.overload();
      piGetHostTarget.implementation = function () {
        return null;
      };
      appliedVpnProxyHooks.push(piGetHostTarget);
      logI('[+] ProxyInfo.getHost hooked');
    } catch (err) {
      logW('[!] ProxyInfo.getHost hook failed: ' + err);
    }

    try {
      const piGetPortTarget = PIClass.getPort.overload();
      piGetPortTarget.implementation = function () {
        return -1;
      };
      appliedVpnProxyHooks.push(piGetPortTarget);
      logI('[+] ProxyInfo.getPort hooked');
    } catch (err) {
      logW('[!] ProxyInfo.getPort hook failed: ' + err);
    }

    try {
      const piGetPacFileUrlTarget = PIClass.getPacFileUrl.overload();
      piGetPacFileUrlTarget.implementation = function () {
        return null;
      };
      appliedVpnProxyHooks.push(piGetPacFileUrlTarget);
      logI('[+] ProxyInfo.getPacFileUrl hooked');
    } catch (err) {
      logW('[!] ProxyInfo.getPacFileUrl hook failed: ' + err);
    }

    try {
      const piGetSocketAddressTarget = PIClass.getSocketAddress.overload();
      piGetSocketAddressTarget.implementation = function () {
        return null;
      };
      appliedVpnProxyHooks.push(piGetSocketAddressTarget);
      logI('[+] ProxyInfo.getSocketAddress hooked');
    } catch (err) {
      logW('[!] ProxyInfo.getSocketAddress hook failed: ' + err);
    }

    try {
      const piMakeProxyTarget = PIClass.makeProxy.overload();
      piMakeProxyTarget.implementation = function () {
        return JProxyClass.NO_PROXY.value;
      };
      appliedVpnProxyHooks.push(piMakeProxyTarget);
      logI('[+] ProxyInfo.makeProxy hooked');
    } catch (err) {
      logW('[!] ProxyInfo.makeProxy hook failed: ' + err);
    }

    try {
      const piToStringTarget = PIClass.toString.overload();
      piToStringTarget.implementation = function () {
        return 'DIRECT';
      };
      appliedVpnProxyHooks.push(piToStringTarget);
      logI('[+] ProxyInfo.toString hooked');
    } catch (err) {
      logW('[!] ProxyInfo.toString hook failed: ' + err);
    }

    try {
      const piIsPacProxyTarget = PIClass.isPacProxy.overload();
      piIsPacProxyTarget.implementation = function () {
        return false;
      };
      appliedVpnProxyHooks.push(piIsPacProxyTarget);
      logI('[+] ProxyInfo.isPacProxy hooked');
    } catch (err) {
      logW('[!] ProxyInfo.isPacProxy hook failed: ' + err);
    }

    try {
      const piIsValidTarget = PIClass.isValid.overload();
      piIsValidTarget.implementation = function () {
        return false;
      };
      appliedVpnProxyHooks.push(piIsValidTarget);
      logI('[+] ProxyInfo.isValid hooked');
    } catch (err) {
      logW('[!] ProxyInfo.isValid hook failed: ' + err);
    }
  } catch (err) {
    logE('[!] Failed to access android.net.ProxyInfo: ' + err);
  }
  
  // ------------------------------------------------------------------
  // android.net.Proxy.getProxy(Context, String) — modern accessor
  // ------------------------------------------------------------------
  // Returns a java.net.Proxy directly, distinct from the deprecated
  // getHost/getPort accessors hooked earlier in this function.
  try {
    const ProxyClass = Java.use('android.net.Proxy');
    const JProxyClass2 = Java.use('java.net.Proxy');
    const getProxyTarget = ProxyClass.getProxy.overload('android.content.Context', 'java.lang.String');
    getProxyTarget.implementation = function (ctx, url) {
      return JProxyClass2.NO_PROXY.value;
    };
    appliedVpnProxyHooks.push(getProxyTarget);
    logI('[+] android.net.Proxy.getProxy(Context, String) hooked');
  } catch (err) {
    logW('[!] android.net.Proxy.getProxy(Context, String) hook failed: ' + err);
  }
}

function revertVpnProxyDetectionBypass() {
  for (const target of appliedVpnProxyHooks) {
    try {
      target.implementation = null;
    } catch (err) {
      logW('[!] Failed to revert a VPN/proxy-detection hook: ' + err);
    }
  }
  appliedVpnProxyHooks.length = 0;
  logI('[*] VPN/proxy detection bypass reverted.');
}

/**
 * Geo-restriction bypass.
 *
 * Spoofs carrier and network-country identity, independent of locale
 * and timezone (see applyLocaleSpoof() for those):
 *
 *   - TelephonyManager.getNetworkOperatorName() / getSimOperatorName() -> geoSpoofValues.operatorName
 *   - TelephonyManager.getSimCarrierIdName()                            -> geoSpoofValues.operatorName
 *   - TelephonyManager.getNetworkOperator() / getSimOperator()          -> geoSpoofValues.plmn
 *   - TelephonyManager.getNetworkCountryIso() / getSimCountryIso()      -> geoSpoofValues.countryIso
 *   - SubscriptionInfo.getCountryIso()/getCarrierName()/getMcc()/
 *     getMnc()/getMccString()/getMncString()                            -> derived from the same values
 *
 * SubscriptionInfo exposes the same carrier/country/PLMN identity
 * through the multi-SIM subscription API surface that some modern
 * apps read from instead of TelephonyManager directly.
 *
 * Gated by geoRestrictionBypassEnabled, independent of
 * localeSpoofEnabled — a caller may want carrier/region identity
 * spoofed for content-availability checks without also changing the
 * app's displayed language, currency, or date/time formatting.
 *
 * References:
 *   https://developer.android.com/reference/android/telephony/TelephonyManager#getNetworkOperatorName()
 *   https://developer.android.com/reference/android/telephony/TelephonyManager#getSimOperatorName()
 *   https://developer.android.com/reference/android/telephony/TelephonyManager#getSimCarrierIdName()
 *   https://developer.android.com/reference/android/telephony/TelephonyManager#getNetworkOperator()
 *   https://developer.android.com/reference/android/telephony/TelephonyManager#getSimOperator()
 *   https://developer.android.com/reference/android/telephony/TelephonyManager#getNetworkCountryIso()
 *   https://developer.android.com/reference/android/telephony/TelephonyManager#getSimCountryIso()
 *   https://developer.android.com/reference/android/telephony/SubscriptionInfo
 */
function applyGeoRestrictionBypass() {
  try {
    var TM1 = Java.use("android.telephony.TelephonyManager");
    var getNetworkOperatorNameTarget = TM1.getNetworkOperatorName.overload();
    getNetworkOperatorNameTarget.implementation = function () {
      return geoSpoofValues.operatorName;
    };
    appliedGeoHooks.push(getNetworkOperatorNameTarget);
    logI("[+] TelephonyManager.getNetworkOperatorName hooked");
  } catch (err) {
    logW("[!] Failed to hook getNetworkOperatorName: " + err);
  }

  try {
    var TM2 = Java.use("android.telephony.TelephonyManager");
    var getSimOperatorNameTarget = TM2.getSimOperatorName.overload();
    getSimOperatorNameTarget.implementation = function () {
      return geoSpoofValues.operatorName;
    };
    appliedGeoHooks.push(getSimOperatorNameTarget);
    logI("[+] TelephonyManager.getSimOperatorName hooked");
  } catch (err) {
    logW("[!] Failed to hook getSimOperatorName: " + err);
  }

  try {
    var TM3 = Java.use("android.telephony.TelephonyManager");
    var getSimCarrierIdNameTarget = TM3.getSimCarrierIdName.overload();
    getSimCarrierIdNameTarget.implementation = function () {
      return geoSpoofValues.operatorName;
    };
    appliedGeoHooks.push(getSimCarrierIdNameTarget);
    logI("[+] TelephonyManager.getSimCarrierIdName hooked");
  } catch (err) {
    logW("[!] Failed to hook getSimCarrierIdName: " + err);
  }

  try {
    var TM4 = Java.use("android.telephony.TelephonyManager");
    var getNetworkOperatorTarget = TM4.getNetworkOperator.overload();
    getNetworkOperatorTarget.implementation = function () {
      return geoSpoofValues.plmn;
    };
    appliedGeoHooks.push(getNetworkOperatorTarget);
    logI("[+] TelephonyManager.getNetworkOperator hooked");
  } catch (err) {
    logW("[!] Failed to hook getNetworkOperator: " + err);
  }

  try {
    var TM5 = Java.use("android.telephony.TelephonyManager");
    var getSimOperatorTarget = TM5.getSimOperator.overload();
    getSimOperatorTarget.implementation = function () {
      return geoSpoofValues.plmn;
    };
    appliedGeoHooks.push(getSimOperatorTarget);
    logI("[+] TelephonyManager.getSimOperator hooked");
  } catch (err) {
    logW("[!] Failed to hook getSimOperator: " + err);
  }

  try {
    var TM6 = Java.use("android.telephony.TelephonyManager");
    var getNetworkCountryIsoTarget = TM6.getNetworkCountryIso.overload();
    getNetworkCountryIsoTarget.implementation = function () {
      return geoSpoofValues.countryIso;
    };
    appliedGeoHooks.push(getNetworkCountryIsoTarget);
    logI("[+] TelephonyManager.getNetworkCountryIso hooked");
  } catch (err) {
    logW("[!] Failed to hook getNetworkCountryIso: " + err);
  }

  try {
    var TM7 = Java.use("android.telephony.TelephonyManager");
    var getSimCountryIsoTarget = TM7.getSimCountryIso.overload();
    getSimCountryIsoTarget.implementation = function () {
      return geoSpoofValues.countryIso;
    };
    appliedGeoHooks.push(getSimCountryIsoTarget);
    logI("[+] TelephonyManager.getSimCountryIso hooked");
  } catch (err) {
    logW("[!] Failed to hook getSimCountryIso: " + err);
  }

  // SubscriptionInfo (android.telephony.SubscriptionInfo) exposes the
  // same carrier/country/PLMN identity as TelephonyManager above, but
  // through the multi-SIM subscription API surface some modern apps
  // read from instead. geoSpoofValues.plmn (MCC+MNC) is split into its two
  // halves for the separate getMcc()/getMnc()/getMccString()/
  // getMncString() getters. getIccId()/getNumber() are handled in
  // applyDeviceIdSpoof() instead, since they identify the SIM/line
  // rather than the network/carrier.
  try {
    const SubscriptionInfoClass = Java.use('android.telephony.SubscriptionInfo');

    // A malformed geoSpoofValues.plmn (wrong length) would otherwise slice
    // into a nonsensical MCC/MNC — e.g. parseInt() on an empty or
    // partial MNC segment yields NaN, which is not a valid Java int
    // and risks a JNI-boundary error when returned from getMcc()/
    // getMnc(). getValidatedMccMnc() (shared with generateImsi(), see its
    // declaration) validates and falls back to a known-good default.
    const { mcc, mnc } = getValidatedMccMnc(geoSpoofValues.plmn, 'GeoRestriction');

    const hookNoArgReturning = (methodName, returnValue) => {
      try {
        const target = SubscriptionInfoClass[methodName].overload();
        target.implementation = function () {
          return returnValue;
        };
        appliedGeoHooks.push(target);
        logI(`[+] SubscriptionInfo.${methodName} hooked`);
      } catch (err) {
        logW(`[!] SubscriptionInfo.${methodName} hook failed (expected on some API levels): ` + err);
      }
    };

    hookNoArgReturning('getCountryIso', geoSpoofValues.countryIso);
    hookNoArgReturning('getCarrierName', geoSpoofValues.operatorName);
    hookNoArgReturning('getMccString', mcc);
    hookNoArgReturning('getMncString', mnc);
    hookNoArgReturning('getMcc', parseInt(mcc, 10));
    hookNoArgReturning('getMnc', parseInt(mnc, 10));
  } catch (err) {
    logE('[!] Failed to access android.telephony.SubscriptionInfo: ' + err);
  }
}

function revertGeoRestrictionBypass() {
  for (const target of appliedGeoHooks) {
    try {
      target.implementation = null;
    } catch (err) {
      logW('[!] Failed to revert a geo-restriction hook: ' + err);
    }
  }
  appliedGeoHooks.length = 0;
  logI('[*] Geo-restriction bypass reverted.');
}

/**
 * Locale and timezone spoofing.
 *
 *   - Locale.getCountry() / getLanguage()                     -> localeSpoofValues.country / localeSpoofValues.language
 *   - Locale.setDefault(Locale) / setDefault(Category, Locale) -> localeSpoofValues.language_localeSpoofValues.country
 *   - TimeZone.getID()                                         -> localeSpoofValues.timezoneId
 *   - Configuration.getLocales() / LocaleList.getDefault()     -> [spoofed locale]
 *
 * getLanguage() is hooked alongside getCountry() so that any Locale
 * instance — not only the JVM default — reports the spoofed language
 * to callers that detect device language directly from a Locale
 * object.
 *
 * The JVM-wide default locale is changed via Locale.setDefault()
 * rather than by hooking the Locale.getDefault() getter, since hooking
 * the getter to return a separately constructed Locale instance
 * creates a divergence between what explicit callers observe and the
 * actual default the platform's internal locale/resource-resolution
 * machinery reads. setDefault() instead mutates the single underlying
 * value all callers read from.
 *
 * Configuration.getLocales() and LocaleList.getDefault() are hooked
 * independently of Locale.setDefault(), since API 24+ introduced
 * per-app ordered locale lists as the platform-recommended mechanism
 * for reading a device's language preference; a caller using
 * Resources.getConfiguration().getLocales() or LocaleList.getDefault()
 * reads a separate state from java.util.Locale.getDefault() and would
 * otherwise observe the real device locale despite the hooks above.
 * Each of these two hooks constructs a fresh LocaleList on every
 * invocation rather than returning one shared instance to every
 * caller; returning a single shared instance across every
 * Configuration/Resources context was found to corrupt internal
 * locale-resolution state, producing a null LocaleList during system
 * dialog inflation (AllCapsTransformationMethod reads
 * Configuration.getLocales().get(0)). Both hooks are installed only
 * if a one-time trial construction of the LocaleList succeeds, so a
 * construction failure leaves the original methods untouched.
 *
 * android.os.LocaleList carries a single constructor,
 * LocaleList(Locale...), compiled to a Locale[] parameter; Frida's
 * reflection-based invocation requires an explicit Java array for
 * this parameter rather than a bare Locale argument.
 *
 * Gated by localeSpoofEnabled, independent of
 * geoRestrictionBypassEnabled — see applyGeoRestrictionBypass().
 *
 * References:
 *   https://developer.android.com/reference/java/util/Locale#getCountry()
 *   https://developer.android.com/reference/java/util/Locale#getLanguage()
 *   https://developer.android.com/reference/java/util/Locale#setDefault(java.util.Locale)
 *   https://developer.android.com/reference/java/util/Locale#setDefault(java.util.Locale.Category,%20java.util.Locale)
 *   https://developer.android.com/reference/java/util/TimeZone#getID()
 *   https://developer.android.com/reference/android/content/res/Configuration#getLocales()
 *   https://developer.android.com/reference/android/os/LocaleList#getDefault()
 *   https://developer.android.com/reference/android/os/LocaleList
 */
function applyLocaleSpoof() {
  try {
    var LocaleClass1 = Java.use("java.util.Locale");
    var getCountryTarget = LocaleClass1.getCountry.overload();
    getCountryTarget.implementation = function () {
      return localeSpoofValues.country;
    };
    appliedLocaleHooks.push(getCountryTarget);
    logI("[+] Locale.getCountry hooked");
  } catch (err) {
    logW("[!] Failed to hook Locale.getCountry: " + err);
  }

  try {
    var LocaleClassLang = Java.use("java.util.Locale");
    var getLanguageTarget = LocaleClassLang.getLanguage.overload();
    getLanguageTarget.implementation = function () {
      return localeSpoofValues.language;
    };
    appliedLocaleHooks.push(getLanguageTarget);
    logI("[+] Locale.getLanguage hooked");
  } catch (err) {
    logW("[!] Failed to hook Locale.getLanguage: " + err);
  }

  // Capture the real JVM-wide defaults BEFORE mutating them via
  // setDefault() below, so revertLocaleSpoof() can restore the exact
  // pre-hook state. Unlike the method hooks above (reverted by clearing
  // .implementation), setDefault() is a one-shot mutation of shared JVM
  // state with no "implementation" to null out — reverting it means
  // calling setDefault() again with the originals.
  var spoofedLocale = null;
  try {
    var LocaleClass2 = Java.use("java.util.Locale");
    originalDefaultLocale = LocaleClass2.getDefault.overload().call(LocaleClass2);
    spoofedLocale = LocaleClass2.$new(localeSpoofValues.language, localeSpoofValues.country);
    LocaleClass2.setDefault.overload('java.util.Locale').call(LocaleClass2, spoofedLocale);
    logI("[+] Locale.setDefault applied");
  } catch (err) {
    logW("[!] Failed to apply Locale.setDefault: " + err);
  }

  // Locale.Category (DISPLAY, FORMAT; API 24+) defaults are set
  // explicitly as well, since setDefault(Locale) alone does not
  // guarantee an existing per-category override is replaced.
  try {
    var LocaleClass3 = Java.use("java.util.Locale");
    var CategoryClass = Java.use("java.util.Locale$Category");
    if (spoofedLocale !== null) {
      originalDisplayLocale = LocaleClass3.getDefault.overload('java.util.Locale$Category').call(LocaleClass3, CategoryClass.DISPLAY.value);
      originalFormatLocale = LocaleClass3.getDefault.overload('java.util.Locale$Category').call(LocaleClass3, CategoryClass.FORMAT.value);
      LocaleClass3.setDefault.overload('java.util.Locale$Category', 'java.util.Locale').call(LocaleClass3, CategoryClass.DISPLAY.value, spoofedLocale);
      LocaleClass3.setDefault.overload('java.util.Locale$Category', 'java.util.Locale').call(LocaleClass3, CategoryClass.FORMAT.value, spoofedLocale);
      logI("[+] Locale.setDefault(Category) applied for DISPLAY and FORMAT");
    }
  } catch (err) {
    logW("[!] Failed to apply category-specific Locale.setDefault: " + err);
  }

  try {
    var TimeZoneClass = Java.use("java.util.TimeZone");
    var getIDTarget = TimeZoneClass.getID.overload();
    getIDTarget.implementation = function () {
      return localeSpoofValues.timezoneId;
    };
    appliedLocaleHooks.push(getIDTarget);
    logI("[+] TimeZone.getID hooked");
  } catch (err) {
    logW("[!] Failed to hook TimeZone.getID: " + err);
  }

  function buildSpoofedLocaleList() {
    var LocaleListClass = Java.use("android.os.LocaleList");
    var LocaleClass4 = Java.use("java.util.Locale");
    var localeForList = LocaleClass4.$new(localeSpoofValues.language, localeSpoofValues.country);
    var localeArray = Java.array("java.util.Locale", [localeForList]);
    return LocaleListClass.$new(localeArray);
  }

  var localeListConstructionOk = false;
  try {
    buildSpoofedLocaleList();
    localeListConstructionOk = true;
  } catch (err) {
    logE("[!] LocaleList construction failed, skipping Configuration.getLocales and LocaleList.getDefault hooks: " + err);
  }

  if (localeListConstructionOk) {
    try {
      var ConfigurationClass = Java.use("android.content.res.Configuration");
      var getLocalesTarget = ConfigurationClass.getLocales.overload();
      getLocalesTarget.implementation = function () {
        try {
          return buildSpoofedLocaleList();
        } catch (e) {
          logW("[!] Configuration.getLocales spoof failed: " + e);
          return this.getLocales();
        }
      };
      appliedLocaleHooks.push(getLocalesTarget);
      logI("[+] Configuration.getLocales hooked");
    } catch (err) {
      logW("[!] Failed to hook Configuration.getLocales: " + err);
    }

    try {
      var LocaleListClass2 = Java.use("android.os.LocaleList");
      var getDefaultLocaleListTarget = LocaleListClass2.getDefault.overload();
      getDefaultLocaleListTarget.implementation = function () {
        try {
          return buildSpoofedLocaleList();
        } catch (e) {
          logW("[!] LocaleList.getDefault spoof failed: " + e);
          return this.getDefault();
        }
      };
      appliedLocaleHooks.push(getDefaultLocaleListTarget);
      logI("[+] LocaleList.getDefault hooked");
    } catch (err) {
      logW("[!] Failed to hook LocaleList.getDefault: " + err);
    }
  }
}

function revertLocaleSpoof() {
  for (const target of appliedLocaleHooks) {
    try {
      target.implementation = null;
    } catch (err) {
      logW('[!] Failed to revert a locale-spoof method hook: ' + err);
    }
  }
  appliedLocaleHooks.length = 0;

  // Restore the JVM-wide default locale(s) mutated by Locale.setDefault()
  // in applyLocaleSpoof(). Only restored if we actually captured an
  // original (i.e. the spoof was actually applied), and restoration is
  // best-effort — a failure here still clears the captured state so a
  // stale value is never reused on a later re-apply.
  try {
    var LocaleClassRevert = Java.use("java.util.Locale");
    if (originalDefaultLocale !== null) {
      LocaleClassRevert.setDefault.overload('java.util.Locale').call(LocaleClassRevert, originalDefaultLocale);
    }
    if (originalDisplayLocale !== null || originalFormatLocale !== null) {
      var CategoryClassRevert = Java.use("java.util.Locale$Category");
      if (originalDisplayLocale !== null) {
        LocaleClassRevert.setDefault.overload('java.util.Locale$Category', 'java.util.Locale').call(LocaleClassRevert, CategoryClassRevert.DISPLAY.value, originalDisplayLocale);
      }
      if (originalFormatLocale !== null) {
        LocaleClassRevert.setDefault.overload('java.util.Locale$Category', 'java.util.Locale').call(LocaleClassRevert, CategoryClassRevert.FORMAT.value, originalFormatLocale);
      }
    }
    logI('[*] Locale.setDefault state restored.');
  } catch (err) {
    logW('[!] Failed to restore original Locale.setDefault state: ' + err);
  } finally {
    originalDefaultLocale = null;
    originalDisplayLocale = null;
    originalFormatLocale = null;
  }

  logI('[*] Locale/timezone spoofing reverted.');
}

/**
 * Resolves a string configuration value nested under a named group in
 * Gadget's parameters object (e.g. parameters.geoSpoofValues.operatorName),
 * preferring it over the module-level default when the group and key
 * are present and correctly typed. Mirrors resolveBooleanFlag() for
 * string-valued settings: a missing group or key silently falls back
 * to the default, while a present key of the wrong type is logged and
 * the default is retained.
 */
function resolveStringValue(parameters, groupKey, fieldKey, currentDefault) {  if (!parameters || !(groupKey in parameters)) {
    return currentDefault;
  }
  const group = parameters[groupKey];
  if (typeof group !== 'object' || group === null || !(fieldKey in group)) {
    return currentDefault;
  }
  const value = group[fieldKey];
  if (typeof value !== 'string') {
    logW(`[init] parameters.${groupKey}.${fieldKey} expected string, got ${typeof value} — using default (${currentDefault})`);
    return currentDefault;
  }
  return value;
}

/**
 * Resolves a string-array configuration value, preferring the value
 * supplied in Gadget's parameters object over the module-level
 * default when present and correctly typed (an array in which every
 * element is a string). Mirrors resolveStringValue() and
 * resolveBooleanFlag() for array-valued settings.
 */
function resolveStringArrayValue(parameters, key, currentDefault) {
  if (!parameters || !(key in parameters)) {
    return currentDefault;
  }
  const value = parameters[key];
  if (!Array.isArray(value) || !value.every((v) => typeof v === 'string')) {
    logW(`[init] parameters.${key} expected an array of strings, got ${typeof value} — using default`);
    return currentDefault;
  }
  return value;
}

/**
 * Resolves an array-valued configuration entry whose elements are
 * objects (e.g. nativeHooks, nativePatches) rather than strings —
 * only array-ness is validated here; malformed individual entries are
 * caught per-entry by applyNativeHooks()/applyNativePatches() instead,
 * consistent with this engine's fail-safe-per-item design elsewhere.
 */
function resolveArrayValue(parameters, key, currentDefault) {
  if (!parameters || !(key in parameters)) {
    return currentDefault;
  }
  const value = parameters[key];
  if (!Array.isArray(value)) {
    logW(`[init] parameters.${key} expected an array, got ${typeof value} — using default`);
    return currentDefault;
  }
  return value;
}

/**
 * Resolves the javaHooks configuration array, preferring the value
 * supplied in Gadget's parameters over the module-level default
 * (defaultJavaHooks) when present and correctly typed. Unlike
 * resolveStringArrayValue(), element shape isn't validated here
 * beyond being an array — malformed individual hook entries are
 * caught per-hook by applyHookWithRetry()/applyJavaHook() instead,
 * consistent with this engine's fail-safe-per-item design elsewhere.
 */
function resolveJavaHooksArray(parameters, currentDefault) {
  if (!parameters || !('javaHooks' in parameters)) {
    return currentDefault;
  }
  const value = parameters.javaHooks;
  if (!Array.isArray(value)) {
    logW(`[init] parameters.javaHooks expected an array, got ${typeof value} — using default`);
    return currentDefault;
  }
  return value;
}

/**
 * Resolves a string-to-string configuration map with a closed key
 * set, merging any user-supplied keys over the module defaults. Only
 * keys already present in defaults are accepted from the supplied
 * object — an unrecognized key is silently ignored, and a recognized
 * key with a non-string value is logged and its default retained.
 * Suited to value maps where the set of valid keys is fixed (e.g.
 * buildPropSpoofValues' known Build fields).
 */
function resolveMergedStringMap(parameters, groupKey, defaults) {
  if (!parameters || !(groupKey in parameters)) {
    return defaults;
  }
  const supplied = parameters[groupKey];
  if (typeof supplied !== 'object' || supplied === null) {
    logW(`[init] parameters.${groupKey} expected object, got ${typeof supplied} — using defaults`);
    return defaults;
  }
  const merged = Object.assign({}, defaults);
  for (const key of Object.keys(defaults)) {
    if (key in supplied) {
      if (typeof supplied[key] === 'string') {
        merged[key] = supplied[key];
      } else {
        logW(`[init] parameters.${groupKey}.${key} expected string, got ${typeof supplied[key]} — using default (${defaults[key]})`);
      }
    }
  }
  return merged;
}

/**
 * Resolves a string-to-string configuration map with an open-ended
 * key set, merging any user-supplied keys over the module defaults.
 * Unlike resolveMergedStringMap(), any string-valued key in the
 * supplied object is accepted, not only keys already present in
 * defaults — suited to value maps where the key space is inherently
 * unbounded (e.g. systemPropertySpoofValues, where any ro., persist.,
 * property name is a valid key).
 */
function resolveOpenStringMap(parameters, groupKey, defaults) {
  if (!parameters || !(groupKey in parameters)) {
    return defaults;
  }
  const supplied = parameters[groupKey];
  if (typeof supplied !== 'object' || supplied === null) {
    logW(`[init] parameters.${groupKey} expected object, got ${typeof supplied} — using defaults`);
    return defaults;
  }
  const merged = Object.assign({}, defaults);
  for (const [key, value] of Object.entries(supplied)) {
    if (typeof value === 'string') {
      merged[key] = value;
    } else {
      logW(`[init] parameters.${groupKey}.${key} expected string, got ${typeof value} — ignoring this key`);
    }
  }
  return merged;
}

/**
 * Resolves a two-level, authority-keyed configuration map (e.g.
 * contentProviderSpoofValues: { authority: { key: value } }), merging
 * any user-supplied authority/key entries over the module defaults.
 * Both the authority set and the key set within each authority are
 * open-ended — a caller may add an entirely new authority, or add new
 * keys to an existing one, without an engine change. An authority
 * entry that isn't itself an object is rejected with a warning and
 * skipped; a non-string value for a given key within an authority is
 * rejected with a warning and that key is skipped, leaving the rest
 * of that authority's map intact.
 */
function resolveNestedStringMap(parameters, groupKey, defaults) {
  if (!parameters || !(groupKey in parameters)) {
    return defaults;
  }
  const supplied = parameters[groupKey];
  if (typeof supplied !== 'object' || supplied === null) {
    logW(`[init] parameters.${groupKey} expected object, got ${typeof supplied} — using defaults`);
    return defaults;
  }

  const merged = {};
  for (const [authority, kv] of Object.entries(defaults)) {
    merged[authority] = Object.assign({}, kv);
  }

  for (const [authority, suppliedKv] of Object.entries(supplied)) {
    if (typeof suppliedKv !== 'object' || suppliedKv === null) {
      logW(`[init] parameters.${groupKey}.${authority} expected object, got ${typeof suppliedKv} — ignoring this authority`);
      continue;
    }
    if (!merged[authority]) {
      merged[authority] = {};
    }
    for (const [key, value] of Object.entries(suppliedKv)) {
      if (typeof value === 'string') {
        merged[authority][key] = value;
      } else {
        logW(`[init] parameters.${groupKey}.${authority}.${key} expected string, got ${typeof value} — ignoring this key`);
      }
    }
  }

  return merged;
}

/**
 * Suspicious-package hiding and spoofing.
 *
 * Prevents an app from detecting root managers, root-cloaking tools,
 * Xposed/LSPosed frameworks, patchers, and emulator packages by
 * filtering them out of every PackageManager/LauncherApps enumeration
 * and lookup surface, and by throwing NameNotFoundException for
 * direct lookups of a suspicious package name:
 *
 *   - PackageManager.getPackageInfo(String, int)
 *   - PackageManager.getPackageInfo(String, PackageInfoFlags)          [API 33+]
 *   - PackageManager.getApplicationInfo(String, int)
 *   - PackageManager.getApplicationInfo(String, ApplicationInfoFlags)  [API 33+]
 *   - PackageManager.getInstalledPackages(int)
 *   - PackageManager.getInstalledPackages(long, int)                  [API 33+]
 *   - PackageManager.getInstalledPackages(PackageInfoFlags)           [API 33+]
 *   - PackageManager.getInstalledApplications(int)
 *   - PackageManager.getInstalledApplications(long, int)              [API 33+]
 *   - PackageManager.getInstalledApplications(ApplicationInfoFlags)   [API 33+]
 *   - PackageManager.queryIntentActivities(Intent, int)
 *   - PackageManager.queryIntentActivities(Intent, ResolveInfoFlags)  [API 33+]
 *   - LauncherApps.getActivityList(String, UserHandle)
 *
 * The API 33+ PackageInfoFlags/ApplicationInfoFlags/ResolveInfoFlags
 * overloads are hooked in addition to the legacy int/long overloads,
 * since they are the platform-recommended API for apps targeting API
 * 33+ and are functionally distinct overloads rather than variants of
 * the ones above.
 *
 * queryIntentActivities() against an ACTION_MAIN/CATEGORY_LAUNCHER
 * intent is a common alternative to getInstalledPackages() for
 * enumerating launchable apps, returning List<ResolveInfo> rather than
 * PackageInfo/ApplicationInfo; LauncherApps.getActivityList() serves
 * the same purpose for launcher-replacement and profile-aware
 * callers, returning List<LauncherActivityInfo>. Both are filtered
 * through the same generic list-filtering core as the PackageManager
 * methods, via a per-source package-name extractor function, since
 * each return type exposes its package name differently.
 *
 * The suspicious-package set has no built-in list — it is entirely
 * user-supplied via parameters.suspiciousPackagesCustom (root
 * managers, Xposed/LSPosed frameworks, patchers, emulator packages,
 * or anything else the user wants hidden). An empty or absent
 * configuration hides nothing, by design.
 *
 * Native/shell-level enumeration (e.g. a `pm list packages` process
 * spawned via Runtime.exec/ProcessBuilder) is out of scope: that is a
 * general command-execution concern rather than one specific to
 * package-list retrieval.
 *
 * Gated by suspiciousPackageSpoofEnabled — see the module-level flag
 * declaration and its override in init().
 *
 * References:
 *   https://developer.android.com/reference/android/content/pm/PackageManager#getPackageInfo(java.lang.String,%20int)
 *   https://developer.android.com/reference/android/content/pm/PackageManager#getPackageInfo(java.lang.String,%20android.content.pm.PackageManager.PackageInfoFlags)
 *   https://developer.android.com/reference/android/content/pm/PackageManager#getApplicationInfo(java.lang.String,%20int)
 *   https://developer.android.com/reference/android/content/pm/PackageManager#getApplicationInfo(java.lang.String,%20android.content.pm.PackageManager.ApplicationInfoFlags)
 *   https://developer.android.com/reference/android/content/pm/PackageManager#getInstalledPackages(int)
 *   https://developer.android.com/reference/android/content/pm/PackageManager#getInstalledPackages(android.content.pm.PackageManager.PackageInfoFlags)
 *   https://developer.android.com/reference/android/content/pm/PackageManager#getInstalledApplications(int)
 *   https://developer.android.com/reference/android/content/pm/PackageManager#getInstalledApplications(android.content.pm.PackageManager.ApplicationInfoFlags)
 *   https://developer.android.com/reference/android/content/pm/PackageManager#queryIntentActivities(android.content.Intent,%20int)
 *   https://developer.android.com/reference/android/content/pm/PackageManager#queryIntentActivities(android.content.Intent,%20android.content.pm.PackageManager.ResolveInfoFlags)
 *   https://developer.android.com/reference/android/content/pm/LauncherApps#getActivityList(java.lang.String,%20android.os.UserHandle)
 *   https://developer.android.com/reference/android/content/pm/PackageManager.PackageInfoFlags
 *   https://developer.android.com/reference/android/content/pm/PackageManager.ApplicationInfoFlags
 *   https://developer.android.com/reference/android/content/pm/PackageManager.ResolveInfoFlags
 */
function applySuspiciousPackageSpoofing() {
  // No built-in package list — the suspicious-package set is entirely
  // user-supplied via suspiciousPackagesCustom (see its module-level
  // declaration and override in init()). An empty configuration hides
  // nothing, by design.
  const suspiciousSet = new Set();
  for (const pkg of suspiciousPackagesCustom) {
    if (typeof pkg === 'string' && pkg.length > 0) {
      suspiciousSet.add(pkg.toLowerCase());
    }
  }

  function isSuspicious(pkgName) {
    if (!pkgName) return false;
    return suspiciousSet.has(pkgName.toLowerCase());
  }

  /**
   * Shared filtering core: iterates a Java List, drops any element
   * whose extracted package name is suspicious, and returns a new
   * java.util.ArrayList containing the remainder. extractPackageName
   * receives one list element and must return a JS string or null.
   *
   * Elements retrieved via Iterator.next() are typed as
   * java.lang.Object at the bytecode level, since Java generics are
   * erased at compile time; Frida's property/method binding reflects
   * this declared type, not the element's actual runtime class.
   * extractPackageName implementations must therefore Java.cast() each
   * element to its real class before accessing type-specific fields
   * or methods — accessing them on the unwrapped Object reference
   * silently yields undefined rather than throwing, which is why this
   * is easy to miss without per-item error handling.
   */
  function filterGenericList(originalList, extractPackageName) {
    if (!originalList) return null;

    let originalClassName = "<unknown>";
    try {
      originalClassName = originalList.getClass().getName();
    } catch (e) {
      try {
        originalClassName = originalList.class ? originalList.class.getName() : "<unknown>";
      } catch (e2) {
        // Class name is diagnostic only; proceed without it if unavailable.
      }
    }

    let iterator;
    try {
      iterator = originalList.iterator();
    } catch (e) {
      logW(`[SuspiciousPackage] originalList.iterator() failed (class=${originalClassName}): ${e.message}`);
      return originalList;
    }

    try {
      const filteredList = Java.use("java.util.ArrayList").$new();
      let removedCount = 0;

      while (iterator.hasNext()) {
        try {
          const item = iterator.next();
          const pName = extractPackageName(item);
          if (pName && isSuspicious(pName)) {
            removedCount++;
          } else {
            filteredList.add(item);
          }
        } catch (e) {
          logW(`[SuspiciousPackage] Skipped one item during filtering (class=${originalClassName}): ${e.message}`);
        }
      }

      if (removedCount > 0) {
        logD(`[SuspiciousPackage] Filtered ${removedCount} item(s) from ${originalClassName}`);
      }
      return filteredList;
    } catch (e) {
      logW(`[SuspiciousPackage] Error filtering list (class=${originalClassName}): ${e.message}`);
      return originalList;
    }
  }

  /**
   * Resolves the runtime class name of a Frida-wrapped Java reference.
   * getClass() is not reliably bound on values obtained via a
   * declared-interface type (e.g. a List returned from calling the
   * original implementation inside a hook), so the .class property is
   * used as a fallback.
   */
  function resolveClassName(obj) {
    try {
      return obj.getClass().getName();
    } catch (e) {
      try {
        return obj.class ? obj.class.getName() : "<unknown>";
      } catch (e2) {
        return "<unknown>";
      }
    }
  }

  // PackageInfo/ApplicationInfo lists may arrive wrapped in
  // ParceledListSlice (common on API levels below 14); the wrapper is
  // unpacked before filtering and reapplied to the filtered result.
  // itemClassName selects the class each list element is cast to
  // (android.content.pm.PackageInfo or .ApplicationInfo) before its
  // packageName field is read.
  function filterPackageOrAppList(result, itemClassName) {
    if (!result) return null;

    const className = resolveClassName(result);

    try {
      let originalList = result;
      let wasParceled = false;

      if (className === "android.content.pm.ParceledListSlice") {
        originalList = result.getList();
        wasParceled = true;
      }

      const ItemClass = Java.use(itemClassName);
      const filtered = filterGenericList(originalList, (item) => {
        const casted = Java.cast(item, ItemClass);
        return casted.packageName ? casted.packageName.value.toString() : null;
      });

      if (wasParceled) {
        const ParceledListSlice = Java.use("android.content.pm.ParceledListSlice");
        return ParceledListSlice.$new(filtered);
      }
      return filtered;
    } catch (e) {
      logW(`[SuspiciousPackage] Error filtering package/app list (class=${className}): ${e.message}`);
      return result;
    }
  }

  function filterResolveInfoList(result) {
    try {
      const ResolveInfoClass = Java.use("android.content.pm.ResolveInfo");
      return filterGenericList(result, (item) => {
        const casted = Java.cast(item, ResolveInfoClass);
        const activityInfo = casted.activityInfo.value;
        return activityInfo && activityInfo.packageName.value
          ? activityInfo.packageName.value.toString()
          : null;
      });
    } catch (e) {
      logW(`[SuspiciousPackage] Error filtering ResolveInfo list: ${e.message}`);
      return result;
    }
  }

  function filterLauncherActivityList(result) {
    try {
      const LauncherActivityInfoClass = Java.use("android.content.pm.LauncherActivityInfo");
      return filterGenericList(result, (item) => {
        const casted = Java.cast(item, LauncherActivityInfoClass);
        return casted.getComponentName().getPackageName().toString();
      });
    } catch (e) {
      logW(`[SuspiciousPackage] Error filtering LauncherActivityInfo list: ${e.message}`);
      return result;
    }
  }

  try {
    const APM = Java.use("android.app.ApplicationPackageManager");
    const NameNotFoundException = Java.use("android.content.pm.PackageManager$NameNotFoundException");

    try {
      const getPackageInfoIntTarget = APM.getPackageInfo.overload('java.lang.String', 'int');
      getPackageInfoIntTarget.implementation = function (pkgName, flags) {
        if (isSuspicious(pkgName)) {
          logD(`[SuspiciousPackage] Blocked getPackageInfo(int) for: ${pkgName}`);
          throw NameNotFoundException.$new("Package not found");
        }
        return this.getPackageInfo(pkgName, flags);
      };
      appliedSuspiciousPackageHooks.push(getPackageInfoIntTarget);
      logI("[+] getPackageInfo(String, int) hooked");
    } catch (e) { logW("[!] getPackageInfo(String, int) hook failed: " + e); }

    try {
      const getPackageInfoFlagsTarget = APM.getPackageInfo.overload('java.lang.String', 'android.content.pm.PackageManager$PackageInfoFlags');
      getPackageInfoFlagsTarget.implementation = function (pkgName, flags) {
        if (isSuspicious(pkgName)) {
          logD(`[SuspiciousPackage] Blocked getPackageInfo(PackageInfoFlags) for: ${pkgName}`);
          throw NameNotFoundException.$new("Package not found");
        }
        return this.getPackageInfo(pkgName, flags);
      };
      appliedSuspiciousPackageHooks.push(getPackageInfoFlagsTarget);
      logI("[+] getPackageInfo(String, PackageInfoFlags) hooked");
    } catch (e) { logW("[!] getPackageInfo(String, PackageInfoFlags) hook failed: " + e); }

    try {
      const getApplicationInfoIntTarget = APM.getApplicationInfo.overload('java.lang.String', 'int');
      getApplicationInfoIntTarget.implementation = function (pkgName, flags) {
        if (isSuspicious(pkgName)) {
          logD(`[SuspiciousPackage] Blocked getApplicationInfo(int) for: ${pkgName}`);
          throw NameNotFoundException.$new("Package not found");
        }
        return this.getApplicationInfo(pkgName, flags);
      };
      appliedSuspiciousPackageHooks.push(getApplicationInfoIntTarget);
      logI("[+] getApplicationInfo(String, int) hooked");
    } catch (e) { logW("[!] getApplicationInfo(String, int) hook failed: " + e); }

    try {
      const getApplicationInfoFlagsTarget = APM.getApplicationInfo.overload('java.lang.String', 'android.content.pm.PackageManager$ApplicationInfoFlags');
      getApplicationInfoFlagsTarget.implementation = function (pkgName, flags) {
        if (isSuspicious(pkgName)) {
          logD(`[SuspiciousPackage] Blocked getApplicationInfo(ApplicationInfoFlags) for: ${pkgName}`);
          throw NameNotFoundException.$new("Package not found");
        }
        return this.getApplicationInfo(pkgName, flags);
      };
      appliedSuspiciousPackageHooks.push(getApplicationInfoFlagsTarget);
      logI("[+] getApplicationInfo(String, ApplicationInfoFlags) hooked");
    } catch (e) { logW("[!] getApplicationInfo(String, ApplicationInfoFlags) hook failed: " + e); }

    try {
      const getInstalledPackagesIntTarget = APM.getInstalledPackages.overload('int');
      getInstalledPackagesIntTarget.implementation = function (flags) {
        return filterPackageOrAppList(this.getInstalledPackages(flags), "android.content.pm.PackageInfo");
      };
      appliedSuspiciousPackageHooks.push(getInstalledPackagesIntTarget);
      logI("[+] getInstalledPackages(int) hooked");
    } catch (e) { logW("[!] getInstalledPackages(int) hook failed: " + e); }

    try {
      const getInstalledPackagesLongIntTarget = APM.getInstalledPackages.overload('long', 'int');
      getInstalledPackagesLongIntTarget.implementation = function (flags, userId) {
        return filterPackageOrAppList(this.getInstalledPackages(flags, userId), "android.content.pm.PackageInfo");
      };
      appliedSuspiciousPackageHooks.push(getInstalledPackagesLongIntTarget);
      logI("[+] getInstalledPackages(long, int) hooked");
    } catch (e) { logW("[!] getInstalledPackages(long, int) hook failed (expected on API < 33): " + e); }

    try {
      const getInstalledPackagesFlagsTarget = APM.getInstalledPackages.overload('android.content.pm.PackageManager$PackageInfoFlags');
      getInstalledPackagesFlagsTarget.implementation = function (flags) {
        return filterPackageOrAppList(this.getInstalledPackages(flags), "android.content.pm.PackageInfo");
      };
      appliedSuspiciousPackageHooks.push(getInstalledPackagesFlagsTarget);
      logI("[+] getInstalledPackages(PackageInfoFlags) hooked");
    } catch (e) { logW("[!] getInstalledPackages(PackageInfoFlags) hook failed (expected on API < 33): " + e); }

    try {
      const getInstalledApplicationsIntTarget = APM.getInstalledApplications.overload('int');
      getInstalledApplicationsIntTarget.implementation = function (flags) {
        return filterPackageOrAppList(this.getInstalledApplications(flags), "android.content.pm.ApplicationInfo");
      };
      appliedSuspiciousPackageHooks.push(getInstalledApplicationsIntTarget);
      logI("[+] getInstalledApplications(int) hooked");
    } catch (e) { logW("[!] getInstalledApplications(int) hook failed: " + e); }

    try {
      const getInstalledApplicationsLongIntTarget = APM.getInstalledApplications.overload('long', 'int');
      getInstalledApplicationsLongIntTarget.implementation = function (flags, userId) {
        return filterPackageOrAppList(this.getInstalledApplications(flags, userId), "android.content.pm.ApplicationInfo");
      };
      appliedSuspiciousPackageHooks.push(getInstalledApplicationsLongIntTarget);
      logI("[+] getInstalledApplications(long, int) hooked");
    } catch (e) { logW("[!] getInstalledApplications(long, int) hook failed (expected on API < 33): " + e); }

    try {
      const getInstalledApplicationsFlagsTarget = APM.getInstalledApplications.overload('android.content.pm.PackageManager$ApplicationInfoFlags');
      getInstalledApplicationsFlagsTarget.implementation = function (flags) {
        return filterPackageOrAppList(this.getInstalledApplications(flags), "android.content.pm.ApplicationInfo");
      };
      appliedSuspiciousPackageHooks.push(getInstalledApplicationsFlagsTarget);
      logI("[+] getInstalledApplications(ApplicationInfoFlags) hooked");
    } catch (e) { logW("[!] getInstalledApplications(ApplicationInfoFlags) hook failed (expected on API < 33): " + e); }

    try {
      const queryIntentActivitiesIntTarget = APM.queryIntentActivities.overload('android.content.Intent', 'int');
      queryIntentActivitiesIntTarget.implementation = function (intent, flags) {
        return filterResolveInfoList(this.queryIntentActivities(intent, flags));
      };
      appliedSuspiciousPackageHooks.push(queryIntentActivitiesIntTarget);
      logI("[+] queryIntentActivities(Intent, int) hooked");
    } catch (e) { logW("[!] queryIntentActivities(Intent, int) hook failed: " + e); }

    try {
      const queryIntentActivitiesFlagsTarget = APM.queryIntentActivities.overload('android.content.Intent', 'android.content.pm.PackageManager$ResolveInfoFlags');
      queryIntentActivitiesFlagsTarget.implementation = function (intent, flags) {
        return filterResolveInfoList(this.queryIntentActivities(intent, flags));
      };
      appliedSuspiciousPackageHooks.push(queryIntentActivitiesFlagsTarget);
      logI("[+] queryIntentActivities(Intent, ResolveInfoFlags) hooked");
    } catch (e) { logW("[!] queryIntentActivities(Intent, ResolveInfoFlags) hook failed (expected on API < 33): " + e); }

    // resolveActivity() returns a single best-match ResolveInfo (or
    // null) rather than a list; a suspicious match is hidden by
    // returning null (mimicking "no matching activity found") rather
    // than by filtering a collection. Its declared return type is
    // ResolveInfo directly (not a generically-typed List element), so
    // no Java.cast() is needed to access activityInfo here, unlike the
    // list-iteration extractors above.
    function isResolvedActivitySuspicious(result) {
      if (result === null) return false;
      try {
        const activityInfo = result.activityInfo.value;
        const pkgName = activityInfo && activityInfo.packageName.value ? activityInfo.packageName.value.toString() : null;
        return pkgName ? isSuspicious(pkgName) : false;
      } catch (e) {
        return false;
      }
    }

    try {
      const resolveActivityIntTarget = APM.resolveActivity.overload('android.content.Intent', 'int');
      resolveActivityIntTarget.implementation = function (intent, flags) {
        const result = this.resolveActivity(intent, flags);
        if (isResolvedActivitySuspicious(result)) {
          logD("[SuspiciousPackage] Blocked resolveActivity(int) match");
          return null;
        }
        return result;
      };
      appliedSuspiciousPackageHooks.push(resolveActivityIntTarget);
      logI("[+] resolveActivity(Intent, int) hooked");
    } catch (e) { logW("[!] resolveActivity(Intent, int) hook failed: " + e); }

    try {
      const resolveActivityFlagsTarget = APM.resolveActivity.overload('android.content.Intent', 'android.content.pm.PackageManager$ResolveInfoFlags');
      resolveActivityFlagsTarget.implementation = function (intent, flags) {
        const result = this.resolveActivity(intent, flags);
        if (isResolvedActivitySuspicious(result)) {
          logD("[SuspiciousPackage] Blocked resolveActivity(ResolveInfoFlags) match");
          return null;
        }
        return result;
      };
      appliedSuspiciousPackageHooks.push(resolveActivityFlagsTarget);
      logI("[+] resolveActivity(Intent, ResolveInfoFlags) hooked");
    } catch (e) { logW("[!] resolveActivity(Intent, ResolveInfoFlags) hook failed (expected on API < 33): " + e); }

    logI("[*] PackageManager suspicious-package hooks active.");
  } catch (err) {
    logE("[!] Failed to set up PackageManager suspicious-package hooks: " + err);
  }

  try {
    const LauncherAppsClass = Java.use("android.content.pm.LauncherApps");
    const getActivityListTarget = LauncherAppsClass.getActivityList.overload('java.lang.String', 'android.os.UserHandle');
    getActivityListTarget.implementation = function (packageName, user) {
      return filterLauncherActivityList(this.getActivityList(packageName, user));
    };
    appliedSuspiciousPackageHooks.push(getActivityListTarget);
    logI("[+] LauncherApps.getActivityList hooked");
  } catch (err) {
    logW("[!] Failed to hook LauncherApps.getActivityList: " + err);
  }
}

function revertSuspiciousPackageSpoofing() {
  for (const target of appliedSuspiciousPackageHooks) {
    try {
      target.implementation = null;
    } catch (err) {
      logW('[!] Failed to revert a suspicious-package hook: ' + err);
    }
  }
  appliedSuspiciousPackageHooks.length = 0;
  logI('[*] Suspicious-package spoofing reverted.');
}

/**
 * Mock-location detection bypass.
 *
 * Hides mock-location usage from both per-Location-object checks and
 * system-wide app-op checks:
 *
 *   - Location.isFromMockProvider()                         -> false [deprecated in API 31]
 *   - Location.isMock()                                       -> false [API 31+]
 *   - AppOpsManager.checkOp/checkOpNoThrow/unsafeCheckOp/
 *     unsafeCheckOpNoThrow(OPSTR_MOCK_LOCATION, ...)          -> MODE_IGNORED
 *   - AppOpsManager.checkOp/checkOpNoThrow (4-arg, API 36+)    -> MODE_IGNORED
 *
 * Location.isFromMockProvider()/isMock() only describe a single
 * Location object; they do not address the more robust, system-wide
 * check many detection SDKs use instead — querying AppOpsManager for
 * whether any given package has been granted
 * OPSTR_MOCK_LOCATION ("android:mock_location"), the app-op backing
 * Developer Options' "Select mock location app". All four
 * String-argument overloads are hooked because Android has alternated
 * which pair is current/deprecated across API levels (checkOp/
 * checkOpNoThrow were current through API 28, unsafeCheckOp/
 * unsafeCheckOpNoThrow from API 29, and checkOp/checkOpNoThrow again
 * from API 36 alongside new 4-arg attributionTag overloads), so an
 * app built against any of these API levels may call any one of them.
 * MODE_IGNORED is returned rather than MODE_ERRORED, since it is
 * documented as the mode meant to be observed silently rather than
 * risk triggering a SecurityException in a caller that treats
 * MODE_ERRORED as reason to crash on this op.
 *
 * The legacy Settings.Secure "mock_location" key (deprecated since
 * API 23, always reporting empty thereafter, but still read by some
 * backward-compatible detectors) is handled separately via
 * applySecureSettingsSpoof(), not here — see its call site in init(),
 * which combines the key sets required by every enabled
 * Settings-dependent feature into a single hook installation.
 *
 * Gated by mockLocationBypassEnabled — see the module-level flag
 * declaration and its override in init().
 *
 * References:
 *   https://developer.android.com/reference/android/location/Location#isFromMockProvider()
 *   https://developer.android.com/reference/android/location/Location#isMock()
 *   https://developer.android.com/reference/android/app/AppOpsManager#checkOp(java.lang.String,%20int,%20java.lang.String)
 *   https://developer.android.com/reference/android/app/AppOpsManager#checkOpNoThrow(java.lang.String,%20int,%20java.lang.String)
 *   https://developer.android.com/reference/android/app/AppOpsManager#unsafeCheckOp(java.lang.String,%20int,%20java.lang.String)
 *   https://developer.android.com/reference/android/app/AppOpsManager#unsafeCheckOpNoThrow(java.lang.String,%20int,%20java.lang.String)
 *   https://developer.android.com/reference/android/app/AppOpsManager#OPSTR_MOCK_LOCATION
 *   https://developer.android.com/reference/android/app/AppOpsManager#MODE_IGNORED
 *   https://developer.android.com/reference/android/provider/Settings.Secure#ALLOW_MOCK_LOCATION
 */
function applyMockLocationBypass() {
  const OPSTR_MOCK_LOCATION = "android:mock_location";

  try {
    var Location1 = Java.use("android.location.Location");
    var isFromMockProviderTarget = Location1.isFromMockProvider.overload();
    isFromMockProviderTarget.implementation = function () {
      return false;
    };
    appliedMockLocationHooks.push(isFromMockProviderTarget);
    logI("[+] Location.isFromMockProvider hooked");
  } catch (err) {
    logW("[!] Failed to hook Location.isFromMockProvider: " + err);
  }

  try {
    var Location2 = Java.use("android.location.Location");
    var isMockTarget = Location2.isMock.overload();
    isMockTarget.implementation = function () {
      return false;
    };
    appliedMockLocationHooks.push(isMockTarget);
    logI("[+] Location.isMock hooked");
  } catch (err) {
    logW("[!] Failed to hook Location.isMock (expected on API < 31): " + err);
  }

  try {
    const AppOpsManagerClass = Java.use("android.app.AppOpsManager");
    const MODE_IGNORED = AppOpsManagerClass.MODE_IGNORED.value;

    const hookCheckOp3Arg = (methodName) => {
      try {
        const target = AppOpsManagerClass[methodName].overload('java.lang.String', 'int', 'java.lang.String');
        target.implementation = function (op, uid, packageName) {
          if (op === OPSTR_MOCK_LOCATION) {
            return MODE_IGNORED;
          }
          return this[methodName](op, uid, packageName);
        };
        appliedMockLocationHooks.push(target);
        logI(`[+] AppOpsManager.${methodName}(String, int, String) hooked`);
      } catch (err) {
        logW(`[!] AppOpsManager.${methodName}(String, int, String) hook failed: ` + err);
      }
    };

    const hookCheckOp4Arg = (methodName) => {
      try {
        const target = AppOpsManagerClass[methodName].overload('java.lang.String', 'int', 'java.lang.String', 'java.lang.String');
        target.implementation = function (op, uid, packageName, attributionTag) {
          if (op === OPSTR_MOCK_LOCATION) {
            return MODE_IGNORED;
          }
          return this[methodName](op, uid, packageName, attributionTag);
        };
        appliedMockLocationHooks.push(target);
        logI(`[+] AppOpsManager.${methodName}(String, int, String, String) hooked`);
      } catch (err) {
        logW(`[!] AppOpsManager.${methodName}(String, int, String, String) hook failed (expected outside API 36+): ` + err);
      }
    };

    hookCheckOp3Arg('checkOp');
    hookCheckOp3Arg('checkOpNoThrow');
    hookCheckOp3Arg('unsafeCheckOp');
    hookCheckOp3Arg('unsafeCheckOpNoThrow');
    hookCheckOp4Arg('checkOp');
    hookCheckOp4Arg('checkOpNoThrow');
  } catch (err) {
    logE("[!] Failed to set up AppOpsManager mock-location hooks: " + err);
  }
}

function revertMockLocationBypass() {
  for (const target of appliedMockLocationHooks) {
    try {
      target.implementation = null;
    } catch (err) {
      logW('[!] Failed to revert a mock-location hook: ' + err);
    }
  }
  appliedMockLocationHooks.length = 0;
  logI('[*] Mock-location bypass reverted.');
}

/**
 * Build-prop (Tier A) identity spoofing.
 *
 * Spoofs android.os.Build's device-identity fields to a configurable
 * profile, defaulting to a Google Pixel 7 Pro:
 *
 *   MANUFACTURER, MODEL, BRAND, PRODUCT, DEVICE, HARDWARE, BOARD,
 *   BOOTLOADER, HOST, ID, FINGERPRINT, TAGS, TYPE, USER, DISPLAY,
 *   and (on android.os.Build$VERSION) RELEASE, SECURITY_PATCH,
 *   INCREMENTAL, CODENAME.
 *
 * Also hooks the two genuine Build methods, getSerial() and
 * getRadioVersion().
 *
 * Deliberately excludes Build.SUPPORTED_ABIS/SUPPORTED_32_BIT_ABIS/
 * SUPPORTED_64_BIT_ABIS and Build.VERSION.SDK_INT: spoofing ABI lists
 * risks crashing the host app if it subsequently attempts to load a
 * native library for an architecture that doesn't actually exist on
 * the device, and SDK_INT commonly gates the app's own internal code
 * paths. Both require separate, careful treatment and are out of
 * scope here.
 *
 * Mechanism — field mutation, not method hooking:
 *   With the exception of getSerial()/getRadioVersion(), every value
 *   spoofed here is a `public static final` FIELD, not a method —
 *   Interceptor-style `.implementation = ...` hooking does not apply
 *   to field reads. Frida's Java bridge instead permits direct
 *   mutation of the field's stored value
 *   (`BuildClass.FIELD.value = newValue`), which persists for every
 *   subsequent reader, including internal framework code, since there
 *   is only one underlying field slot. This mirrors the
 *   Locale.setDefault() approach used elsewhere in this engine: mutate
 *   the actual state rather than intercept a getter.
 *
 * Known platform limitation:
 *   As of Android 17 (API 37+), ART has been observed to block
 *   reflective writes to public static final Build/Build.VERSION
 *   fields with IllegalAccessException. No workaround for that
 *   specific restriction is implemented here; on an affected device
 *   this module's field writes may fail per-field (each is
 *   independently try/caught and logged) while the rest of the engine
 *   continues to function normally.
 *
 * Gated by buildPropSpoofEnabled — see the module-level flag
 * declaration and its override in init().
 *
 * References:
 *   https://developer.android.com/reference/android/os/Build
 *   https://developer.android.com/reference/android/os/Build#getSerial()
 *   https://developer.android.com/reference/android/os/Build#getRadioVersion()
 */
function applyBuildPropSpoof(values) {
  let BuildClass;
  try {
    BuildClass = Java.use('android.os.Build');
  } catch (err) {
    logE('[!] Failed to access android.os.Build: ' + err);
    return;
  }

  const fieldMap = {
    manufacturer: 'MANUFACTURER',
    model: 'MODEL',
    brand: 'BRAND',
    product: 'PRODUCT',
    device: 'DEVICE',
    hardware: 'HARDWARE',
    board: 'BOARD',
    bootloader: 'BOOTLOADER',
    host: 'HOST',
    id: 'ID',
    fingerprint: 'FINGERPRINT',
    tags: 'TAGS',
    type: 'TYPE',
    user: 'USER',
    display: 'DISPLAY'
  };

  for (const [configKey, fieldName] of Object.entries(fieldMap)) {
    try {
      originalBuildPropFieldValues[fieldName] = BuildClass[fieldName].value;
      BuildClass[fieldName].value = values[configKey];
      logI(`[+] Build.${fieldName} set to "${values[configKey]}"`);
    } catch (err) {
      logW(`[!] Failed to set Build.${fieldName}: ` + err);
    }
  }

  // Build.VERSION.* string fields — a separate nested class from
  // Build itself. SDK_INT is deliberately excluded (see docstring
  // above): it commonly gates the host app's own code paths, unlike
  // these string fields, which are informational.
  try {
    const BuildVersionClass = Java.use('android.os.Build$VERSION');
    const versionFieldMap = {
      release: 'RELEASE',
      securityPatch: 'SECURITY_PATCH',
      incremental: 'INCREMENTAL',
      codename: 'CODENAME'
    };
    for (const [configKey, fieldName] of Object.entries(versionFieldMap)) {
      try {
        originalBuildPropFieldValues['VERSION.' + fieldName] = BuildVersionClass[fieldName].value;
        BuildVersionClass[fieldName].value = values[configKey];
        logI(`[+] Build.VERSION.${fieldName} set to "${values[configKey]}"`);
      } catch (err) {
        logW(`[!] Failed to set Build.VERSION.${fieldName}: ` + err);
      }
    }
  } catch (err) {
    logE('[!] Failed to access android.os.Build$VERSION: ' + err);
  }

  try {
    const getSerialTarget = BuildClass.getSerial.overload();
    getSerialTarget.implementation = function () {
      return values.id || "UNKNOWN";
    };
    appliedBuildMethodHooks.push(getSerialTarget);
    logI("[+] Build.getSerial hooked");
  } catch (err) {
    logW("[!] Failed to hook Build.getSerial (expected on API < 26, or unpermitted without READ_PHONE_STATE): " + err);
  }

  try {
    const getRadioVersionTarget = BuildClass.getRadioVersion.overload();
    getRadioVersionTarget.implementation = function () {
      return null;
    };
    appliedBuildMethodHooks.push(getRadioVersionTarget);
    logI("[+] Build.getRadioVersion hooked");
  } catch (err) {
    logW("[!] Failed to hook Build.getRadioVersion: " + err);
  }

  logI("[*] Build-prop (Tier A) identity spoofing applied.");
}

function revertBuildPropSpoof() {
  let BuildClass;
  try {
    BuildClass = Java.use('android.os.Build');
  } catch (err) {
    logE('[!] Failed to access android.os.Build during revert: ' + err);
    return;
  }

  let BuildVersionClass = null;
  try {
    BuildVersionClass = Java.use('android.os.Build$VERSION');
  } catch (err) {
    logW('[!] Failed to access android.os.Build$VERSION during revert: ' + err);
  }

  for (const [key, originalValue] of Object.entries(originalBuildPropFieldValues)) {
    if (originalValue === undefined) {
      // The original read failed or returned undefined when this
      // field was first spoofed (see applyBuildPropSpoof()); writing
      // undefined back into a Java String field risks a JNI-boundary
      // type error, and there is nothing meaningful to restore.
      continue;
    }
    try {
      if (key.startsWith('VERSION.')) {
        const versionFieldName = key.slice('VERSION.'.length);
        if (BuildVersionClass) {
          BuildVersionClass[versionFieldName].value = originalValue;
        }
      } else {
        BuildClass[key].value = originalValue;
      }
    } catch (err) {
      logW(`[!] Failed to revert Build field for key ${key}: ` + err);
    }
  }

  for (const target of appliedBuildMethodHooks) {
    try {
      target.implementation = null; // Frida's documented revert sentinel — restores the original Java implementation.
    } catch (err) {
      logW('[!] Failed to revert a Build method hook: ' + err);
    }
  }
  appliedBuildMethodHooks.length = 0;

  logI("[*] Build-prop spoofing reverted.");
}

/**
 * System-property spoofing.
 *
 * Hooks android.os.SystemProperties.get(String) and
 * get(String, String), the reflection-accessible (hidden-API, but not
 * SDK-restricted at the bytecode level Frida operates on) methods
 * every raw `ro.*`/`persist.*`/`qemu.*` property read ultimately goes
 * through — including many emulator- and root-detection checks that
 * read properties directly rather than through android.os.Build,
 * and bootloader-lock-state checks (ro.boot.verifiedbootstate,
 * ro.boot.flash.locked) that android.os.Build has no field for at
 * all. android.os.Build's own fields are populated from these same
 * properties, but only once, at Build's class-initialization time —
 * hooking SystemProperties.get() here does not retroactively change
 * already-initialized Build.* fields (applyBuildPropSpoof() mutates
 * those directly, for that reason), but it does cover every other
 * caller that reads a property key directly.
 *
 * The spoofed key set is open-ended and fully configurable via
 * systemPropertySpoofValues (see resolveOpenStringMap()); the
 * built-in starter set covers common bootloader-lock-state and
 * classic-emulator-artifact keys, and is intended to be expanded with
 * additional keys as needed rather than treated as exhaustive.
 *
 * Gated by systemPropertySpoofEnabled, independent of
 * buildPropSpoofEnabled — see the module-level flag declarations and
 * their overrides in init().
 *
 * References:
 *   https://cs.android.com/android/platform/superproject/+/master:frameworks/base/core/java/android/os/SystemProperties.java
 */
function applySystemPropertySpoof(values) {
  let SystemPropertiesClass;
  try {
    SystemPropertiesClass = Java.use('android.os.SystemProperties');
  } catch (err) {
    logE('[!] Failed to access android.os.SystemProperties: ' + err);
    return;
  }

  try {
    const get1Target = SystemPropertiesClass.get.overload('java.lang.String');
    get1Target.implementation = function (key) {
      if (Object.prototype.hasOwnProperty.call(values, key)) {
        return values[key];
      }
      return this.get(key);
    };
    appliedSystemPropertyHooks.push(get1Target);
    logI("[+] SystemProperties.get(String) hooked");
  } catch (err) {
    logW("[!] Failed to hook SystemProperties.get(String): " + err);
  }

  try {
    const get2Target = SystemPropertiesClass.get.overload('java.lang.String', 'java.lang.String');
    get2Target.implementation = function (key, def) {
      if (Object.prototype.hasOwnProperty.call(values, key)) {
        return values[key];
      }
      return this.get(key, def);
    };
    appliedSystemPropertyHooks.push(get2Target);
    logI("[+] SystemProperties.get(String, String) hooked");
  } catch (err) {
    logW("[!] Failed to hook SystemProperties.get(String, String): " + err);
  }

  logI(`[*] System-property spoofing applied for ${Object.keys(values).length} key(s).`);
}

function revertSystemPropertySpoof() {
  for (const target of appliedSystemPropertyHooks) {
    try {
      target.implementation = null;
    } catch (err) {
      logW('[!] Failed to revert a SystemProperties hook: ' + err);
    }
  }
  appliedSystemPropertyHooks.length = 0;
  logI("[*] System-property spoofing reverted.");
}

/**
 * Validates a PLMN (MCC+MNC) string and splits it into its two halves.
 * MCC is always 3 digits; MNC is 2 or 3 digits, so a valid PLMN is always
 * exactly 5 or 6 characters. A malformed value falls back to a known-valid
 * default so a caller never slices a nonsensical MCC/MNC out of a bad
 * config entry.
 *
 * Shared by applyGeoRestrictionBypass() (SubscriptionInfo.getMcc()/getMnc()/
 * getMccString()/getMncString()) and generateImsi() (deviceIdSpoofUseRandom)
 * — a single source of truth so a randomly-generated IMSI's MCC/MNC always
 * matches the configured/spoofed carrier identity in geoSpoofValues.plmn,
 * instead of generateImsi() hardcoding an independent US default that could
 * silently disagree with a non-US geoSpoofValues profile.
 */
const DEFAULT_VALID_PLMN = "310410";

function getValidatedMccMnc(plmn, logTag) {
  const plmnForSplit = (typeof plmn === 'string' && (plmn.length === 5 || plmn.length === 6)) ? plmn : DEFAULT_VALID_PLMN;
  if (plmnForSplit !== plmn) {
    logW(`[${logTag}] plmn "${plmn}" is not 5 or 6 characters — using default "${DEFAULT_VALID_PLMN}" for MCC/MNC-derived values`);
  }
  return { mcc: plmnForSplit.slice(0, 3), mnc: plmnForSplit.slice(3) };
}

/**
 * Random-value generators for deviceIdSpoofUseRandom.
 *
 * IMEI and ICCID include a correct Luhn check digit, since some
 * validation logic checks this independently of the identifier's
 * specific value. Generated MACs are drawn from a small pool of real,
 * publicly-known consumer-device OUI prefixes rather than a
 * fully-random first octet, since a locally-administered-bit pattern
 * (02:xx:xx) or the classic QEMU/VirtualBox prefixes (02:00:00,
 * 08:00:27) is itself a signature of a generated or virtualized
 * address.
 */
function randomDigits(length) {
  let s = '';
  for (let i = 0; i < length; i++) {
    s += Math.floor(Math.random() * 10);
  }
  return s;
}

function randomHex(length) {
  const chars = '0123456789ABCDEF';
  let s = '';
  for (let i = 0; i < length; i++) {
    s += chars[Math.floor(Math.random() * chars.length)];
  }
  return s;
}

function luhnCheckDigit(numberStr) {
  let sum = 0;
  let alternate = true;
  for (let i = numberStr.length - 1; i >= 0; i--) {
    let n = parseInt(numberStr[i], 10);
    if (alternate) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alternate = !alternate;
  }
  return (10 - (sum % 10)) % 10;
}

function generateImei() {
  const body = randomDigits(14);
  return body + luhnCheckDigit(body);
}

function generateMeid() {
  return randomHex(14);
}

function generateIccid() {
  // 89 (telecom industry prefix) + 16 random digits + Luhn check digit = 19 total.
  const body = "89" + randomDigits(16);
  return body + luhnCheckDigit(body);
}

function generateImsi() {
  // MCC/MNC derived from the configured geoSpoofValues.plmn (via the
  // shared getValidatedMccMnc()), not a hardcoded constant, so a randomly
  // generated IMSI stays consistent with whatever carrier/country identity
  // geoRestrictionBypassEnabled is also spoofing. IMSI is always 15 digits
  // total (MCC + MNC + random fill).
  const { mcc, mnc } = getValidatedMccMnc(geoSpoofValues.plmn, 'DeviceId');
  return mcc + mnc + randomDigits(15 - mcc.length - mnc.length);
}

function generatePhoneNumber() {
  return "+1" + randomDigits(10);
}

const REALISTIC_MAC_OUIS = ["3C:5A:B4", "AC:37:43", "F4:F5:D8", "34:14:5F", "88:B1:11"];

function generateMac() {
  const oui = REALISTIC_MAC_OUIS[Math.floor(Math.random() * REALISTIC_MAC_OUIS.length)];
  const suffix = [randomHex(2), randomHex(2), randomHex(2)].join(':');
  return `${oui}:${suffix}`;
}

function generateAdvertisingId() {
  // RFC 4122 version-4 UUID: version nibble fixed to 4, variant nibble
  // constrained to 8/9/A/B.
  const hex = randomHex(32).toLowerCase();
  const variantNibble = "89ab"[Math.floor(Math.random() * 4)];
  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    "4" + hex.slice(13, 16),
    variantNibble + hex.slice(17, 20),
    hex.slice(20, 32)
  ].join('-');
}

function generateInternalIp() {
  // 192.168.0.0/16 is the standard consumer-router private range.
  // Deliberately avoids 10.0.2.x (classic AVD emulator address) and
  // 10.0.0.x so the value is not itself an emulator signature.
  const third = Math.floor(Math.random() * 254) + 1;
  const fourth = Math.floor(Math.random() * 254) + 1;
  return `192.168.${third}.${fourth}`;
}

function generateRandomDeviceIdValues() {
  return {
    androidId: randomHex(16).toLowerCase(),
    imei: generateImei(),
    meid: generateMeid(),
    iccid: generateIccid(),
    imsi: generateImsi(),
    phoneNumber: generatePhoneNumber(),
    wifiMac: generateMac(),
    bluetoothMac: generateMac(),
    advertisingId: generateAdvertisingId(),
    internalIp: generateInternalIp()
  };
}

/**
 * Device-identifier spoofing.
 *
 *   - TelephonyManager.getDeviceId()/(int), getImei()/(int),
 *     getMeid()/(int), getSimSerialNumber() [ICCID],
 *     getSubscriberId() [IMSI], getLine1Number() [phone number]
 *   - NetworkInterface.getHardwareAddress() [Wi-Fi/Ethernet MAC]
 *   - WifiInfo.getMacAddress(), BluetoothAdapter.getAddress() (both
 *     already OS-redacted to "02:00:00:00:00:00" without special
 *     permission since API 23 for every app, real or emulator —
 *     hooked anyway for completeness, though their standalone
 *     detection value is low since the redacted placeholder appears
 *     identically on real devices)
 *   - AdvertisingIdClient.Info.getId()/isLimitAdTrackingEnabled()
 *     (Google Play Services) and the equivalent
 *     androidx.ads.identifier.AdvertisingIdInfo API (a separate,
 *     independent advertising-ID surface some newer apps read from
 *     instead) — both best-effort, gracefully skipped if the
 *     respective class isn't present on the test device/AVD image
 *   - WifiInfo.getIpAddress() [internal IP] — a classic AVD emulator
 *     always reports 10.0.2.15 here, a well-known detection signal
 *
 * Settings.Secure.ANDROID_ID is handled separately, through
 * applySecureSettingsSpoof() — see its call site in init(), which
 * combines every enabled Settings-dependent feature's key/value pairs
 * into a single hook installation.
 *
 * Every hooked TelephonyManager/network/advertising method returns
 * its spoofed value directly, without ever calling through to the
 * original implementation: as of API 29+, several of these throw
 * SecurityException without READ_PRIVILEGED_PHONE_STATE, and calling
 * the original at all would risk that exception surfacing even when
 * the intent is purely to override the result.
 *
 * Values come from either deviceIdSpoofValues (a fixed, configurable
 * profile) or freshly-generated random values, selected by
 * deviceIdSpoofUseRandom — see its resolution in init().
 *
 * Native-layer identifier sources (e.g. code that reads /proc/net or
 * issues raw ioctls for a MAC address rather than going through these
 * Java APIs) are out of scope here, consistent with this engine's
 * existing native/system-layer boundary.
 *
 * Gated by deviceIdSpoofEnabled — see the module-level flag
 * declaration and its override in init().
 *
 * References:
 *   https://developer.android.com/reference/android/telephony/TelephonyManager#getImei()
 *   https://developer.android.com/reference/android/telephony/TelephonyManager#getMeid()
 *   https://developer.android.com/reference/android/telephony/TelephonyManager#getSimSerialNumber()
 *   https://developer.android.com/reference/android/telephony/TelephonyManager#getSubscriberId()
 *   https://developer.android.com/reference/android/telephony/TelephonyManager#getLine1Number()
 *   https://developer.android.com/reference/java/net/NetworkInterface#getHardwareAddress()
 *   https://developer.android.com/reference/android/net/wifi/WifiInfo#getMacAddress()
 *   https://developer.android.com/reference/android/bluetooth/BluetoothAdapter#getAddress()
 */
const DEFAULT_VALID_MAC = "3C:5A:B4:1E:2F:8D";

function isValidMacAddress(mac) {
  return typeof mac === 'string' && /^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/.test(mac);
}

function applyDeviceIdSpoof(values) {
  const hookNoArg = (ClassRef, methodName, returnValue) => {
    try {
      const target = ClassRef[methodName].overload();
      target.implementation = function () {
        return returnValue;
      };
      appliedDeviceIdHooks.push(target);
      logI(`[+] ${methodName}() hooked`);
    } catch (err) {
      logW(`[!] ${methodName}() hook failed: ` + err);
    }
  };

  const hookIntArg = (ClassRef, methodName, returnValue) => {
    try {
      const target = ClassRef[methodName].overload('int');
      target.implementation = function (slotIndex) {
        return returnValue;
      };
      appliedDeviceIdHooks.push(target);
      logI(`[+] ${methodName}(int) hooked`);
    } catch (err) {
      logW(`[!] ${methodName}(int) hook failed (expected on some API levels): ` + err);
    }
  };

  try {
    const TM = Java.use('android.telephony.TelephonyManager');
    hookNoArg(TM, 'getDeviceId', values.imei);
    hookIntArg(TM, 'getDeviceId', values.imei);
    hookNoArg(TM, 'getImei', values.imei);
    hookIntArg(TM, 'getImei', values.imei);
    hookNoArg(TM, 'getMeid', values.meid);
    hookIntArg(TM, 'getMeid', values.meid);
    hookNoArg(TM, 'getSimSerialNumber', values.iccid);
    hookNoArg(TM, 'getSubscriberId', values.imsi);
    hookNoArg(TM, 'getLine1Number', values.phoneNumber);
  } catch (err) {
    logE("[!] Failed to access android.telephony.TelephonyManager: " + err);
  }

  try {
    const NetworkInterfaceClass = Java.use('java.net.NetworkInterface');
    const hwAddrTarget = NetworkInterfaceClass.getHardwareAddress.overload();
    hwAddrTarget.implementation = function () {
      try {
        const macToUse = isValidMacAddress(values.wifiMac) ? values.wifiMac : DEFAULT_VALID_MAC;
        if (macToUse !== values.wifiMac) {
          logW(`[DeviceId] wifiMac "${values.wifiMac}" is not a valid MAC (expected 6 colon-separated hex octets) — using default "${DEFAULT_VALID_MAC}"`);
        }
        const macBytes = macToUse.split(':').map((h) => {
          const v = parseInt(h, 16);
          return v > 127 ? v - 256 : v; // Java byte is signed; fold high values into negative range.
        });
        return Java.array('byte', macBytes);
      } catch (innerErr) {
        logW("[!] Failed to build spoofed hardware address, falling back to original: " + innerErr);
        return this.getHardwareAddress();
      }
    };
    appliedDeviceIdHooks.push(hwAddrTarget);
    logI(`[+] NetworkInterface.getHardwareAddress hooked (spoofed as ${values.wifiMac})`);
  } catch (err) {
    logW("[!] Failed to hook NetworkInterface.getHardwareAddress: " + err);
  }

  try {
    const WifiInfoClass = Java.use('android.net.wifi.WifiInfo');
    const wifiMacTarget = WifiInfoClass.getMacAddress.overload();
    wifiMacTarget.implementation = function () {
      return values.wifiMac;
    };
    appliedDeviceIdHooks.push(wifiMacTarget);
    logI("[+] WifiInfo.getMacAddress hooked");
  } catch (err) {
    logW("[!] Failed to hook WifiInfo.getMacAddress: " + err);
  }

  try {
    const BluetoothAdapterClass = Java.use('android.bluetooth.BluetoothAdapter');
    const btAddrTarget = BluetoothAdapterClass.getAddress.overload();
    btAddrTarget.implementation = function () {
      return values.bluetoothMac;
    };
    appliedDeviceIdHooks.push(btAddrTarget);
    logI("[+] BluetoothAdapter.getAddress hooked");
  } catch (err) {
    logW("[!] Failed to hook BluetoothAdapter.getAddress: " + err);
  }

  try {
    const AdInfoClass = Java.use('com.google.android.gms.ads.identifier.AdvertisingIdClient$Info');
    const gmsGetIdTarget = AdInfoClass.getId.overload();
    gmsGetIdTarget.implementation = function () {
      return values.advertisingId;
    };
    appliedDeviceIdHooks.push(gmsGetIdTarget);
    logI(`[+] AdvertisingIdClient.Info.getId hooked`);
  } catch (err) {
    logW("[!] Google Play Services AdvertisingIdClient not present or hook failed (expected on AOSP-only images): " + err);
  }

  try {
    const AdInfoClass2 = Java.use('com.google.android.gms.ads.identifier.AdvertisingIdClient$Info');
    const gmsLimitTarget = AdInfoClass2.isLimitAdTrackingEnabled.overload();
    gmsLimitTarget.implementation = function () {
      return false;
    };
    appliedDeviceIdHooks.push(gmsLimitTarget);
    logI(`[+] AdvertisingIdClient.Info.isLimitAdTrackingEnabled hooked`);
  } catch (err) {
    logW("[!] AdvertisingIdClient.Info.isLimitAdTrackingEnabled hook failed (expected on AOSP-only images): " + err);
  }

  // androidx.ads.identifier is a separate, independent advertising-ID
  // API Google introduced alongside the Play-Services-based one above
  // (distinct package, same getId()/isLimitAdTrackingEnabled() shape).
  // Some newer apps/SDKs read from this one instead.
  try {
    const AndroidxAdInfoClass = Java.use('androidx.ads.identifier.AdvertisingIdInfo');
    const androidxGetIdTarget = AndroidxAdInfoClass.getId.overload();
    androidxGetIdTarget.implementation = function () {
      return values.advertisingId;
    };
    appliedDeviceIdHooks.push(androidxGetIdTarget);
    logI(`[+] androidx.ads.identifier.AdvertisingIdInfo.getId hooked`);
  } catch (err) {
    logW("[!] androidx.ads.identifier.AdvertisingIdInfo not present or hook failed: " + err);
  }

  try {
    const AndroidxAdInfoClass2 = Java.use('androidx.ads.identifier.AdvertisingIdInfo');
    const androidxLimitTarget = AndroidxAdInfoClass2.isLimitAdTrackingEnabled.overload();
    androidxLimitTarget.implementation = function () {
      return false;
    };
    appliedDeviceIdHooks.push(androidxLimitTarget);
    logI(`[+] androidx.ads.identifier.AdvertisingIdInfo.isLimitAdTrackingEnabled hooked`);
  } catch (err) {
    logW("[!] androidx.ads.identifier.AdvertisingIdInfo.isLimitAdTrackingEnabled hook failed: " + err);
  }

  // Internal IP: WifiInfo.getIpAddress() returns a Java int with the
  // low-order byte first (little-endian), the classic AOSP convention;
  // a plain dotted-quad string requires this conversion, unlike the
  // String-returning identifiers above.
  try {
    const WifiInfoClass2 = Java.use('android.net.wifi.WifiInfo');
    const ipSource = (typeof values.internalIp === 'string' && values.internalIp.length > 0)
      ? values.internalIp
      : '192.168.1.42';
    const ipParts = ipSource.split('.').map(Number);
    const ipInt = (ipParts[0] & 0xFF) | ((ipParts[1] & 0xFF) << 8) | ((ipParts[2] & 0xFF) << 16) | ((ipParts[3] & 0xFF) << 24);
    const ipAddrTarget = WifiInfoClass2.getIpAddress.overload();
    ipAddrTarget.implementation = function () {
      return ipInt;
    };
    appliedDeviceIdHooks.push(ipAddrTarget);
    logI(`[+] WifiInfo.getIpAddress hooked (spoofed as ${ipSource})`);
  } catch (err) {
    logW("[!] Failed to hook WifiInfo.getIpAddress: " + err);
  }

  // SubscriptionInfo's ICCID/phone-number getters — the carrier/country
  // identity getters on the same class are handled in
  // applyGeoRestrictionBypass() instead, since they identify the
  // network/carrier rather than the SIM/line.
  try {
    const SubscriptionInfoClass = Java.use('android.telephony.SubscriptionInfo');

    try {
      const iccIdTarget = SubscriptionInfoClass.getIccId.overload();
      iccIdTarget.implementation = function () {
        return values.iccid;
      };
      appliedDeviceIdHooks.push(iccIdTarget);
      logI("[+] SubscriptionInfo.getIccId hooked");
    } catch (err) {
      logW("[!] SubscriptionInfo.getIccId hook failed: " + err);
    }

    try {
      const numberTarget = SubscriptionInfoClass.getNumber.overload();
      numberTarget.implementation = function () {
        return values.phoneNumber;
      };
      appliedDeviceIdHooks.push(numberTarget);
      logI("[+] SubscriptionInfo.getNumber hooked");
    } catch (err) {
      logW("[!] SubscriptionInfo.getNumber hook failed (expected on some API levels): " + err);
    }
  } catch (err) {
    logE('[!] Failed to access android.telephony.SubscriptionInfo: ' + err);
  }

  logI("[*] Device-identifier spoofing applied.");
}

function revertDeviceIdSpoof() {
  for (const target of appliedDeviceIdHooks) {
    try {
      target.implementation = null;
    } catch (err) {
      logW('[!] Failed to revert a device-identifier hook: ' + err);
    }
  }
  appliedDeviceIdHooks.length = 0;
  logI("[*] Device-identifier spoofing reverted.");
}

/**
 * Hardware-feature spoofing.
 *
 * Forces PackageManager.hasSystemFeature() to report a configurable
 * set of hardware features as present regardless of the device's
 * actual capabilities. Emulators commonly lack real telephony,
 * camera, and sensor hardware, and hasSystemFeature() checks against
 * those specific feature strings (android.hardware.telephony,
 * android.hardware.camera, android.hardware.sensor.accelerometer,
 * etc.) are a common emulator-detection signal independent of any
 * identifier or build-prop value.
 *
 * getSystemAvailableFeatures() (returning the full FeatureInfo[]
 * array) is not covered here: constructing well-formed FeatureInfo
 * instances (glEsVersion, reqGlEsVersion, flags) for injection is
 * substantially more involved than a boolean override, and
 * hasSystemFeature() is the far more commonly checked entry point.
 *
 * Gated by hardwareFeatureSpoofEnabled — see the module-level flag
 * declaration and its override in init().
 *
 * References:
 *   https://developer.android.com/reference/android/content/pm/PackageManager#hasSystemFeature(java.lang.String)
 *   https://developer.android.com/reference/android/content/pm/PackageManager#hasSystemFeature(java.lang.String,%20int)
 */
function applyHardwareFeatureSpoof(features) {
  const featureSet = new Set(features);

  try {
    const PM = Java.use('android.app.ApplicationPackageManager');

    try {
      const feature1Target = PM.hasSystemFeature.overload('java.lang.String');
      feature1Target.implementation = function (name) {
        if (featureSet.has(name)) {
          return true;
        }
        return this.hasSystemFeature(name);
      };
      appliedHardwareFeatureHooks.push(feature1Target);
      logI("[+] PackageManager.hasSystemFeature(String) hooked");
    } catch (err) {
      logW("[!] PackageManager.hasSystemFeature(String) hook failed: " + err);
    }

    try {
      const feature2Target = PM.hasSystemFeature.overload('java.lang.String', 'int');
      feature2Target.implementation = function (name, version) {
        if (featureSet.has(name)) {
          return true;
        }
        return this.hasSystemFeature(name, version);
      };
      appliedHardwareFeatureHooks.push(feature2Target);
      logI("[+] PackageManager.hasSystemFeature(String, int) hooked");
    } catch (err) {
      logW("[!] PackageManager.hasSystemFeature(String, int) hook failed: " + err);
    }
  } catch (err) {
    logE("[!] Failed to access android.app.ApplicationPackageManager: " + err);
  }

  logI(`[*] Hardware-feature spoofing applied for ${featureSet.size} feature(s).`);
}

function revertHardwareFeatureSpoof() {
  for (const target of appliedHardwareFeatureHooks) {
    try {
      target.implementation = null;
    } catch (err) {
      logW('[!] Failed to revert a hardware-feature hook: ' + err);
    }
  }
  appliedHardwareFeatureHooks.length = 0;
  logI("[*] Hardware-feature spoofing reverted.");
}

/**
 * ContentResolver.query()/call() spoofing, keyed by authority.
 *
 * Covers callers that bypass the Settings.Secure/Global/System
 * convenience methods (handled by applySecureSettingsSpoof()) and the
 * TelephonyManager/device-identifier methods (handled by
 * applyDeviceIdSpoof()) and read the underlying ContentProvider
 * directly — a real pattern, confirmed via static analysis of an
 * actual test app during this engine's development, where a static
 * initializer read Settings.Secure.ANDROID_ID before
 * applySecureSettingsSpoof()'s hook was installed (see the
 * Java.performNow() rationale below) and separately, apps that query
 * content://settings/... or content://com.google.android.gsf.gservices
 * directly rather than through any convenience method at all.
 *
 * The spoofed key/value data is organized by authority
 * (contentProviderSpoofValues: { authority: { key: value } }) rather
 * than being hardcoded to the two authorities above, so that adding
 * coverage for a further provider is a configuration change, not an
 * engine change. The "settings" authority is the one exception with
 * built-in special-case logic: its call() protocol distinguishes
 * GET_secure/GET_global/GET_system from PUT_* by method name (see
 * below), a convention specific to that one provider and not assumed
 * to generalize to whatever other authorities a user configures.
 *
 * Coverage split — call() vs. query():
 *   ContentResolver.call() is given full coverage: on modern Android,
 *   Settings.NameValueCache's own getString()/getInt() implementation
 *   is itself primarily backed by call() (Bundle-based, not
 *   Cursor-based), returning a Bundle with a "value" key — spoofing
 *   this is a straightforward, well-defined Bundle substitution. For
 *   the "settings" authority specifically, the call() hook checks the
 *   method parameter against AOSP's GET_secure/GET_global/GET_system
 *   convention (SETTINGS_GET_METHOD_RE) before spoofing, since a
 *   PUT_* call for the same key must be allowed to actually write —
 *   spoofing it too would silently drop the write while the caller
 *   believes it succeeded. Every other configured authority is
 *   matched on authority + arg only, without a method-name
 *   restriction, since no other provider's call() naming convention
 *   is assumed or has been independently verified.
 *
 *   ContentResolver.query() and the equivalent
 *   ContentProviderClient.query() (a separate class some AOSP code
 *   paths use to bypass ContentResolver entirely) are given
 *   best-effort coverage: a caller can request an arbitrary column
 *   projection and construct whatever selection/selectionArgs it
 *   wants, and there is no single correct way to synthesize a Cursor
 *   matching every possible shape. extractKeyCandidates() collects
 *   every plausible key encoding in a query — the URI's last path
 *   segment, a literal name='<key>' fragment, or a name=? placeholder
 *   mapped to its correct position among possibly multiple ANDed
 *   conditions — rather than trusting the first one found, since the
 *   URI path segment for a query against a bare
 *   content://settings/secure URI is the table name ("secure"), not a
 *   key, and treating it as one would incorrectly let the real,
 *   unspoofed query through. The default projection when the caller
 *   passes null/empty is a single "value" column, matching AOSP's own
 *   internal fallback projection for this exact query shape, so a
 *   caller reading cursor.getString(0) against a null projection gets
 *   the value at the index it expects. Cursor construction is wrapped
 *   in a try/catch (safeBuildCursor()) so a projection shape this
 *   logic doesn't handle well falls through to the real query rather
 *   than crashing the host app with an uncaught exception.
 *
 * Hook installation is guarded against being repeated by a second
 * init() call (contentProviderHooksApplied) — Frida's
 * method-implementation assignment replaces the current
 * implementation rather than chaining, so a second, uncoordinated
 * installation would leave dispose() unable to distinguish the true
 * original from an intermediate hooked state.
 *
 * Reversion sets each hook's implementation to null rather than
 * attempting to capture and restore a snapshot of the prior
 * implementation — capturing overload().implementation as a stand-in
 * for "the original" is unreliable, since repeated .overload(sig)
 * calls for the same signature may return the same underlying wrapper
 * object Frida caches internally, in which case reading .implementation
 * from it after already having assigned a hook reads back the hook
 * itself, not the true original. null is Frida's documented sentinel
 * for restoring a method's original implementation and carries no
 * such risk; this same correction was applied to every other module
 * in this engine that previously used the capture-based pattern.
 *
 * Gated by contentProviderSpoofEnabled. The "settings" authority's
 * key/value map is merged with the ADB/mock-location/android_id keys
 * derived from other flags at apply time, so this module and
 * applySecureSettingsSpoof() never disagree about the "settings"
 * authority's values — see the combined construction in init().
 *
 * References:
 *   https://developer.android.com/reference/android/content/ContentResolver#call(java.lang.String,%20java.lang.String,%20java.lang.String,%20android.os.Bundle)
 *   https://developer.android.com/reference/android/content/ContentResolver#call(android.net.Uri,%20java.lang.String,%20java.lang.String,%20android.os.Bundle)
 *   https://developer.android.com/reference/android/content/ContentResolver#query(android.net.Uri,%20java.lang.String[],%20java.lang.String,%20java.lang.String[],%20java.lang.String)
 *   https://developer.android.com/reference/android/content/ContentProviderClient
 *   https://developer.android.com/reference/android/database/MatrixCursor
 */
const SETTINGS_AUTHORITY = 'settings';
const SETTINGS_GET_METHOD_RE = /^GET_(secure|global|system)$/;
let contentProviderHooksApplied = false;

/**
 * Extracts every plausible settings-style key name from a query's
 * URI/selection, rather than returning the first match found. See the
 * module docstring above for why the URI-path-segment candidate alone
 * is insufficient. \bname\b requires a word boundary so a column
 * named my_name isn't matched, and the regexes are intentionally
 * case-sensitive (no /i flag), since SQL column names are
 * case-sensitive and "NAME" is not the same identifier as "name".
 */
function extractKeyCandidates(uri, selection, selectionArgs) {
  const candidates = [];

  try {
    const lastSegment = uri.getLastPathSegment();
    if (lastSegment !== null && lastSegment.length > 0) {
      candidates.push(lastSegment);
    }
  } catch (e) {
    // no URI-path candidate available
  }

  if (selection !== null) {
    try {
      const directRe = /\bname\b\s*=\s*['"]([^'"]+)['"]/g;
      let m;
      while ((m = directRe.exec(selection)) !== null) {
        candidates.push(m[1]);
      }
    } catch (e) {
      // malformed selection string; no direct-literal candidates
    }

    if (selectionArgs !== null) {
      try {
        const paramRe = /\bname\b\s*=\s*\?/g;
        let m;
        while ((m = paramRe.exec(selection)) !== null) {
          const qPosInMatch = m[0].lastIndexOf('?');
          const absoluteQPos = m.index + qPosInMatch;
          let qCount = 0;
          for (let i = 0; i < absoluteQPos; i++) {
            if (selection.charAt(i) === '?') qCount++;
          }
          if (qCount < selectionArgs.length) {
            candidates.push(selectionArgs[qCount]);
          }
        }
      } catch (e) {
        // malformed selection string; no parameterized candidates
      }
    }
  }

  return candidates;
}

function findMatchingKey(candidates, keyValues) {
  for (const candidate of candidates) {
    if (candidate !== null && Object.prototype.hasOwnProperty.call(keyValues, candidate)) {
      return candidate;
    }
  }
  return null;
}

function buildSyntheticCursor(projection, value) {
  const MatrixCursor = Java.use('android.database.MatrixCursor');
  const StringClass = Java.use('java.lang.String');

  const columnNames = (projection !== null && projection.length > 0)
    ? projection
    : Java.array('java.lang.String', ['value']);

  let targetIndex = 0;
  for (let i = 0; i < columnNames.length; i++) {
    if (columnNames[i] === 'value') {
      targetIndex = i;
      break;
    }
  }

  const rowValues = [];
  for (let i = 0; i < columnNames.length; i++) {
    rowValues.push(i === targetIndex ? StringClass.$new(value) : null);
  }

  const cursor = MatrixCursor.$new(columnNames);
  cursor.addRow(Java.array('java.lang.Object', rowValues));
  return cursor;
}

function safeBuildCursor(projection, value) {
  try {
    return buildSyntheticCursor(projection, value);
  } catch (e) {
    logE(`[ContentProviderSpoof] cursor build failed, falling through to real query: ${e}`);
    return null;
  }
}

function buildCallResultBundle(value) {
  const BundleClass = Java.use('android.os.Bundle');
  const bundle = BundleClass.$new();
  bundle.putString('value', value);
  return bundle;
}

function applyContentProviderSpoof(authorityKeyValues) {
  if (contentProviderHooksApplied) {
    logW('[ContentProviderSpoof] hooks already applied — skipping re-application');
    return;
  }
  contentProviderHooksApplied = true;

  /**
   * Looks up a spoofed value for a given authority+key, or undefined
   * if that authority isn't configured or doesn't contain that key.
   * undefined (rather than null) distinguishes "no configured spoof"
   * from a legitimately-configured empty string.
   */
  function resolveSpoofValue(authority, key) {
    if (authority === null || key === null) return undefined;
    const kv = authorityKeyValues[authority];
    if (!kv) return undefined;
    return Object.prototype.hasOwnProperty.call(kv, key) ? kv[key] : undefined;
  }

  try {
    const ContentResolverClass = Java.use('android.content.ContentResolver');

    try {
      const call3Target = ContentResolverClass.call.overload('java.lang.String', 'java.lang.String', 'java.lang.String', 'android.os.Bundle');
      call3Target.implementation = function (authority, method, arg, extras) {
        try {
          // The GET_secure/GET_global/GET_system vs. PUT_* distinction
          // is specific to the Settings provider's own call() protocol;
          // it is not assumed to generalize to every configured
          // authority, so it only gates the "settings" authority.
          if (authority === SETTINGS_AUTHORITY && method !== null && !SETTINGS_GET_METHOD_RE.test(method)) {
            return this.call(authority, method, arg, extras);
          }
          const spoofValue = resolveSpoofValue(authority, arg);
          if (spoofValue !== undefined) {
            logD(`[ContentProviderSpoof] call(authority=${authority}, method=${method}, arg=${arg}) intercepted`);
            return buildCallResultBundle(spoofValue);
          }
        } catch (innerErr) {
          logW(`[ContentProviderSpoof] call(String) hook failed: ${innerErr}`);
        }
        return this.call(authority, method, arg, extras);
      };
      appliedContentProviderHooks.push(call3Target);
      logI('[+] ContentResolver.call(String, String, String, Bundle) hooked');
    } catch (err) {
      logW('[!] ContentResolver.call(String, String, String, Bundle) hook failed: ' + err);
    }

    try {
      const call4Target = ContentResolverClass.call.overload('android.net.Uri', 'java.lang.String', 'java.lang.String', 'android.os.Bundle');
      call4Target.implementation = function (uri, method, arg, extras) {
        try {
          let authority = null;
          try {
            authority = uri.getAuthority();
          } catch (e) {
            // leave authority null; falls through to original call below
          }
          if (authority === SETTINGS_AUTHORITY && method !== null && !SETTINGS_GET_METHOD_RE.test(method)) {
            return this.call(uri, method, arg, extras);
          }
          const spoofValue = resolveSpoofValue(authority, arg);
          if (spoofValue !== undefined) {
            logD(`[ContentProviderSpoof] call(Uri authority=${authority}, method=${method}, arg=${arg}) intercepted`);
            return buildCallResultBundle(spoofValue);
          }
        } catch (innerErr) {
          logW(`[ContentProviderSpoof] call(Uri) hook failed: ${innerErr}`);
        }
        return this.call(uri, method, arg, extras);
      };
      appliedContentProviderHooks.push(call4Target);
      logI('[+] ContentResolver.call(Uri, String, String, Bundle) hooked');
    } catch (err) {
      logW('[!] ContentResolver.call(Uri, String, String, Bundle) hook failed (expected on API < 29): ' + err);
    }
  } catch (err) {
    logE('[!] Failed to access android.content.ContentResolver for call(): ' + err);
  }

  function makeQueryImplementation(originalMethodName) {
    return function (uri, projection, selection, selectionArgs, sortOrder) {
      let authority = null;
      try {
        authority = uri.getAuthority();
      } catch (e) {
        // leave authority null; falls through to the original query below
      }

      const kv = authority !== null ? authorityKeyValues[authority] : undefined;
      if (kv) {
        const candidates = extractKeyCandidates(uri, selection, selectionArgs);
        const key = findMatchingKey(candidates, kv);
        if (key !== null) {
          const cursor = safeBuildCursor(projection, kv[key]);
          if (cursor !== null) {
            logD(`[ContentProviderSpoof] ${originalMethodName}(authority=${authority}, key=${key}) best-effort intercepted`);
            return cursor;
          }
        }
      }

      return this[originalMethodName](uri, projection, selection, selectionArgs, sortOrder);
    };
  }

  try {
    const ContentResolverClass2 = Java.use('android.content.ContentResolver');
    const queryTarget = ContentResolverClass2.query.overload(
      'android.net.Uri', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String'
    );
    queryTarget.implementation = makeQueryImplementation('query');
    appliedContentProviderHooks.push(queryTarget);
    logI('[+] ContentResolver.query(Uri, String[], String, String[], String) hooked');
  } catch (err) {
    logW('[!] ContentResolver.query(...) hook failed: ' + err);
  }

  try {
    const ContentProviderClientClass = Java.use('android.content.ContentProviderClient');
    const clientQueryTarget = ContentProviderClientClass.query.overload(
      'android.net.Uri', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String'
    );
    clientQueryTarget.implementation = makeQueryImplementation('query');
    appliedContentProviderHooks.push(clientQueryTarget);
    logI('[+] ContentProviderClient.query(Uri, String[], String, String[], String) hooked');
  } catch (err) {
    logW('[!] ContentProviderClient.query(...) hook failed: ' + err);
  }

  logI(`[*] ContentProvider spoofing applied for authorities: ${Object.keys(authorityKeyValues).join(', ')}`);
}

function revertContentProviderSpoof() {
  for (const target of appliedContentProviderHooks) {
    try {
      target.implementation = null;
    } catch (err) {
      logW('[!] Failed to revert a ContentResolver hook: ' + err);
    }
  }
  appliedContentProviderHooks.length = 0;
  contentProviderHooksApplied = false;
  logI('[*] ContentProvider spoofing reverted.');
}

/**
 * Config-driven native (.so-level) hooking.
 *
 * Frida 17+ API usage confirmed against
 * https://frida.re/news/2025/05/17/frida-17-0-0-released/ :
 *   Process.getModuleByName(name) then instance methods/properties on
 *   the returned Module (.getExportByName(), .base) — not the removed
 *   static Module.getExportByName()/Module.getBaseAddress().
 *
 * Two hook modes, selected per entry by whether argTypes AND
 * returnType are both supplied:
 *
 *   Typed mode — Interceptor.replace() with NativeFunction (to call
 *   the original, per Frida's documented pattern for chaining to the
 *   original implementation from inside a replacement) and
 *   NativeCallback (the replacement). Full type safety across all
 *   Frida native types, including float/double/struct returns, which
 *   a raw pointer-level retval.replace() cannot handle correctly.
 *   Supports onCall.nop (skip the original entirely).
 *
 *   Raw mode (argTypes/returnType omitted) — Interceptor.attach(). No
 *   type information required; args[i] and retval are plain
 *   NativePointer, read/write only as pointer-sized values.
 *   onCall.nop is not supported in this mode (attach() cannot skip
 *   the call it observes).
 *
 * Target-address resolution (one of three, in this priority order):
 *   symbolName      — an exported symbol.
 *   offset          — a hex string offset from the module's base
 *                     address; the ASLR-safe way to target a
 *                     non-exported/static function found via reverse
 *                     engineering.
 *   absoluteAddress — used as-is. ASLR-unsafe; included for
 *                     completeness, not recommended.
 *
 * Gated by nativeHooksEnabled — see the module-level flag declaration
 * and its override in init().
 *
 * References:
 *   https://frida.re/docs/javascript-api/ (Process, Module, Interceptor, NativeFunction, NativeCallback)
 */
function coerceNativeValue(type, rawValue) {
  switch (type) {
    case 'void':
      return undefined;
    case 'bool':
      return !!rawValue;
    case 'int8': case 'uint8': case 'int16': case 'uint16':
    case 'int32': case 'uint32': case 'int': case 'uint': case 'char': case 'uchar':
      return typeof rawValue === 'number' ? rawValue : parseInt(rawValue, 10);
    case 'int64':
      return typeof rawValue === 'string' ? int64(rawValue) : rawValue;
    case 'uint64':
      return typeof rawValue === 'string' ? uint64(rawValue) : rawValue;
    case 'float': case 'double':
      return typeof rawValue === 'number' ? rawValue : parseFloat(rawValue);
    case 'pointer':
      return ptr(rawValue);
    default:
      // Struct/array-typed values are passed through as-is; the
      // config is responsible for supplying something Frida can
      // marshal for that type.
      return rawValue;
  }
}

function resolveTargetAddress(hookConfig) {
  const module = Process.getModuleByName(hookConfig.moduleName);

  if (hookConfig.symbolName) {
    return module.getExportByName(hookConfig.symbolName);
  }
  if (hookConfig.offset) {
    return module.base.add(ptr(hookConfig.offset));
  }
  if (hookConfig.absoluteAddress) {
    return ptr(hookConfig.absoluteAddress);
  }
  throw new Error('hook entry must supply one of symbolName, offset, or absoluteAddress');
}

function describeNativeTarget(hookConfig, targetAddr) {
  const locator = hookConfig.symbolName
    ? `symbol=${hookConfig.symbolName}`
    : hookConfig.offset
      ? `offset=${hookConfig.offset}`
      : `address=${hookConfig.absoluteAddress}`;
  return `${hookConfig.moduleName}!${locator} @ ${targetAddr}`;
}

function applyTypedNativeHook(hookConfig, targetAddr) {
  const onCall = hookConfig.onCall || {};
  const original = new NativeFunction(targetAddr, hookConfig.returnType, hookConfig.argTypes);

  const replacement = new NativeCallback(function (...args) {
    try {
      const tag = describeNativeTarget(hookConfig, targetAddr);
  
      if (onCall.logArgs) {
        args.forEach((a, i) => {
          logD(`[NativeHook][typed] ${tag} arg[${i}] (${hookConfig.argTypes[i]}) = ${a}`);
        });
      }
  
      if (onCall.modifyArgs) {
        for (const [idxStr, newVal] of Object.entries(onCall.modifyArgs)) {
          const idx = parseInt(idxStr, 10);
          const t = hookConfig.argTypes[idx];
          args[idx] = coerceNativeValue(t, newVal);
          logD(`[NativeHook][typed] ${tag} overriding arg[${idx}] (${t}) -> ${args[idx]}`);
        }
      }
  
      if (onCall.nop) {
        logD(`[NativeHook][typed] ${tag} NOP — original skipped`);
        return Object.prototype.hasOwnProperty.call(onCall, 'forceReturn')
          ? coerceNativeValue(hookConfig.returnType, onCall.forceReturn)
          : coerceNativeValue(hookConfig.returnType, 0);
      }
  
      const result = original(...args);
  
      if (onCall.logReturn) {
        logD(`[NativeHook][typed] ${tag} original return (${hookConfig.returnType}) = ${result}`);
      }
  
      if (Object.prototype.hasOwnProperty.call(onCall, 'forceReturn')) {
        const forced = coerceNativeValue(hookConfig.returnType, onCall.forceReturn);
        logD(`[NativeHook][typed] ${tag} forced return -> ${forced}`);
        return forced;
      }
  
      return result;
    } catch (e) {
      logE(`[NativeHook][typed] callback threw: ${e}`);
      if (hookConfig.returnType === 'void') return;
      if (hookConfig.returnType === 'pointer') return ptr(0);
      if (hookConfig.returnType === 'int64' || hookConfig.returnType === 'uint64') return int64(0);
      if (hookConfig.returnType === 'float' || hookConfig.returnType === 'double') return 0.0;
      if (hookConfig.returnType === 'bool') return 0;
      return 0;
    }
  }, hookConfig.returnType, hookConfig.argTypes);

  Interceptor.replace(targetAddr, replacement);
  appliedTypedNativeHookAddresses.push(targetAddr);
  logI(`[+] Typed native hook installed: ${describeNativeTarget(hookConfig, targetAddr)}`);
}

function applyRawNativeHook(hookConfig, targetAddr) {
  const onCall = hookConfig.onCall || {};
  const tag = describeNativeTarget(hookConfig, targetAddr);

  if (onCall.nop) {
    logW(`[NativeHook][raw] ${tag} onCall.nop is not supported in raw mode — ignoring`);
  }
  // Optional, raw-mode-only config field: how many pointer-sized arg slots
  // onCall.logArgs logs. Defaults to 4 (this module's prior fixed count) for
  // backward compatibility. Raw mode has no argTypes to infer the real
  // arity from, so logging a fixed count can print past a function's actual
  // argument list (harmless — just misleading log output, since the extra
  // slots read whatever is in that register/stack position) or stop short
  // of it for a function taking more than 4; set this per-entry to match.
  const rawArgCount = Number.isInteger(hookConfig.rawArgCount) && hookConfig.rawArgCount >= 0
    ? hookConfig.rawArgCount
    : 4;

  const listener = Interceptor.attach(targetAddr, {
    onEnter(args) {
      try {
        if (onCall.logArgs) {
          for (let i = 0; i < rawArgCount; i++) {
            logD(`[NativeHook][raw] ${tag} arg[${i}] = ${args[i]}`);
          }
        }
        if (onCall.modifyArgs) {
          for (const [idxStr, newVal] of Object.entries(onCall.modifyArgs)) {
            const idx = parseInt(idxStr, 10);
            args[idx] = ptr(newVal);
            logD(`[NativeHook][raw] ${tag} overriding arg[${idx}] -> ${args[idx]}`);
          }
        }
      } catch (e) {
        logE(`[NativeHook][raw] ${tag} onEnter threw: ${e}`);
      }
    },
    onLeave(retval) {
      try {
        if (onCall.logReturn) {
          logD(`[NativeHook][raw] ${tag} original return = ${retval}`);
        }
        if (Object.prototype.hasOwnProperty.call(onCall, 'forceReturn')) {
          retval.replace(ptr(onCall.forceReturn));
          logD(`[NativeHook][raw] ${tag} forced return -> ${onCall.forceReturn}`);
        }
      } catch (e) {
        logE(`[NativeHook][raw] ${tag} onLeave threw: ${e}`);
      }
    }
  });

  appliedRawNativeHookListeners.push(listener);
  logI(`[+] Raw native hook installed: ${tag}`);
}

function applyNativeHooks(hooks) {
  for (const hookConfig of hooks) {
    try {
      const targetAddr = resolveTargetAddress(hookConfig);
      const isTyped = Array.isArray(hookConfig.argTypes) && typeof hookConfig.returnType === 'string';
      if (isTyped) {
        applyTypedNativeHook(hookConfig, targetAddr);
      } else {
        applyRawNativeHook(hookConfig, targetAddr);
      }
    } catch (err) {
      logE(`[!] Failed to apply native hook (module=${hookConfig.moduleName}): ${err}`);
    }
  }
  logI(`[*] Native hooks applied: ${appliedTypedNativeHookAddresses.length} typed, ${appliedRawNativeHookListeners.length} raw.`);
}

function revertNativeHooks() {
  for (const addr of appliedTypedNativeHookAddresses) {
    try {
      Interceptor.revert(addr);
    } catch (err) {
      logW(`[!] Failed to revert typed native hook at ${addr}: ${err}`);
    }
  }
  appliedTypedNativeHookAddresses.length = 0;

  for (const listener of appliedRawNativeHookListeners) {
    try {
      listener.detach();
    } catch (err) {
      logW(`[!] Failed to detach raw native hook listener: ${err}`);
    }
  }
  appliedRawNativeHookListeners.length = 0;

  logI('[*] Native hooks reverted.');
}

/**
 * Native code patching (Memory.patchCode()) — a raw instruction-byte
 * edit, not a function hook. This engine cannot validate that
 * patchBytes is well-formed for the target CPU architecture
 * (ARM/ARM64/x86 have entirely different opcode encodings, and
 * endianness applies); a malformed patch can corrupt execution in
 * ways ranging from a crash to silent incorrect behavior elsewhere in
 * the process. The original bytes at the target address are captured
 * before patching and restored verbatim on revert.
 *
 * patchBytes accepts two forms, both equivalent:
 *   ["1F", "20", "03", "D5"]    array of 2-char hex byte strings
 *   "1F2003D5"                  single concatenated hex string
 * The string form must be non-empty and even-length; a malformed
 * string is rejected before any memory is written, so no partial
 * patch is ever applied.
 *
 * Gated by nativePatchesEnabled — see the module-level flag
 * declaration and its override in init().
 */
function applyNativePatches(patches) {
  for (const patchConfig of patches) {
    try {
      const targetAddr = resolveTargetAddress(patchConfig);

      // patchBytes accepts two forms, both equivalent:
      //   ["1F", "20", "03", "D5"]    array of 2-char hex byte strings
      //   "1F2003D5"                  single concatenated hex string
      // The string form is normalized into the array form before any
      // memory is written, so a malformed string is rejected up front
      // and never results in a partial patch.
      const rawPatchBytes = patchConfig.patchBytes;
      let patchBytes;
      if (typeof rawPatchBytes === 'string') {
        if (rawPatchBytes.length === 0 || rawPatchBytes.length % 2 !== 0) {
          throw new Error(`patchBytes string must be non-empty and even-length (got ${rawPatchBytes.length} characters)`);
        }
        const chunks = rawPatchBytes.match(/.{2}/g);
        if (!chunks) {
          throw new Error('patchBytes string could not be split into 2-char hex bytes');
        }
        patchBytes = chunks;
      } else if (Array.isArray(rawPatchBytes)) {
        patchBytes = rawPatchBytes;
      } else {
        throw new Error('patchBytes must be a hex string or an array of 2-char hex byte strings');
      }

      const size = patchBytes.length;

      const originalBytes = targetAddr.readByteArray(size);
      appliedNativePatches.push({ address: targetAddr, originalBytes });

      const newBytes = patchBytes.map((b) => parseInt(b, 16));
      Memory.patchCode(targetAddr, size, function (code) {
        for (let i = 0; i < newBytes.length; i++) {
          code.add(i).writeU8(newBytes[i]);
        }
      });

      logI(`[+] Native patch applied: ${describeNativeTarget(patchConfig, targetAddr)} (${size} byte(s))`);
    } catch (err) {
      logE(`[!] Failed to apply native patch (module=${patchConfig.moduleName}): ${err}`);
    }
  }
  logI(`[*] Native patches applied: ${appliedNativePatches.length}.`);
}

function revertNativePatches() {
  for (const { address, originalBytes } of appliedNativePatches) {
    try {
      const size = originalBytes.byteLength;
      Memory.patchCode(address, size, function (code) {
        code.writeByteArray(originalBytes);
      });
    } catch (err) {
      logW(`[!] Failed to revert native patch at ${address}: ${err}`);
    }
  }
  appliedNativePatches.length = 0;
  logI('[*] Native patches reverted.');
}

/**
 * RegisterNatives discovery/logging.
 *
 * Hooks JNIEnv::RegisterNatives inside libart.so to log, for every native
 * method registered at runtime, its declaring class, name, JNI signature,
 * and the native function pointer's owning module + offset. This recovers
 * the class<->native-function mapping even when:
 *   - the native library's own symbol table is stripped (common under
 *     packers/anti-tamper protections), so readelf/objdump/IDA can't name
 *     the function directly, and
 *   - the app registers natives explicitly via RegisterNatives() rather
 *     than relying on the Java_pkg_Class_method JNI naming convention, so
 *     there is no static name to look up at all.
 *
 * Complements the generic nativeHooks module rather than duplicating it:
 * that one needs a known symbolName/offset per target up front; this one
 * discovers those targets (module + offset) for you, from the one,
 * class-independent, fixed ART entry point every native method
 * registration funnels through — then applyNativeHooks()/nativeHooks can
 * be pointed at whatever this logs.
 *
 * Target resolution: registerNativesLogLocator.symbolName/offset, if
 * either is set, is used as-is (same locator semantics as resolveTargetAddress()
 * for nativeHooks/nativePatches). Otherwise, libart.so's exported symbols
 * are scanned by name heuristic. A production/OEM build commonly ships
 * libart.so with its symbol table stripped — in which case the heuristic
 * finds nothing, this logs a warning, and registerNativesLogLocator must
 * be set manually (e.g. from an AOSP debug build's symbol table for a
 * matching ART/API version, or from your own native-layer analysis).
 * When the heuristic finds more than one candidate symbol — real ART
 * builds can expose template specializations or internal helpers whose
 * names also contain "RegisterNatives" even after excluding CheckJNI —
 * only the first is hooked by default (hooking every match blindly would
 * misinterpret args[1..3] for any match whose real signature isn't
 * exactly RegisterNatives(JNIEnv*, jclass, JNINativeMethod*, jint)); every
 * candidate found is logged so registerNativesLogLocator can pin the
 * correct one if the default pick is wrong for this device's ART build.
 *
 * Gated by registerNativesLogEnabled — see the module-level flag
 * declaration and its override in init(). Values come from
 * registerNativesLogClassFilter and registerNativesLogLocator.
 */
function applyRegisterNativesLog(classFilterList, locator) {
  const classFilter = new Set(classFilterList || []);

  let libart;
  try {
    libart = Process.getModuleByName('libart.so');
  } catch (err) {
    logE('[!] [RegisterNativesLog] libart.so not found: ' + err);
    return;
  }

  let targetAddr = null;
  try {
    if (locator && locator.symbolName) {
      targetAddr = libart.getExportByName(locator.symbolName);
      logI(`[RegisterNativesLog] using configured symbolName: ${locator.symbolName} @ ${targetAddr}`);
    } else if (locator && locator.offset) {
      targetAddr = libart.base.add(ptr(locator.offset));
      logI(`[RegisterNativesLog] using configured offset: ${locator.offset} @ ${targetAddr}`);
    } else {
      const matches = libart.enumerateSymbols().filter((s) =>
        s.name.indexOf('art') >= 0 &&
        s.name.indexOf('JNI') >= 0 &&
        s.name.indexOf('RegisterNatives') >= 0 &&
        s.name.indexOf('CheckJNI') < 0
      );
      if (matches.length === 0) {
        logW('[!] [RegisterNativesLog] no RegisterNatives symbol found in libart.so (symbols may be stripped on this build — set registerNativesLogLocator.symbolName/offset manually)');
        return;
      }
      if (matches.length > 1) {
        logW(`[!] [RegisterNativesLog] ${matches.length} candidate symbols matched — hooking the first only; set registerNativesLogLocator.symbolName to pin a specific one if this is wrong for this build: ${matches.map((m) => m.name).join(', ')}`);
      }
      targetAddr = matches[0].address;
      logI(`[RegisterNativesLog] found at ${targetAddr} (${matches[0].name})`);
    }
  } catch (err) {
    logE('[!] [RegisterNativesLog] failed to resolve target address: ' + err);
    return;
  }

  // Installed directly — no Java.perform()/Java.performNow() wrapper is
  // needed here. Process.getModuleByName()/Interceptor.attach() are pure
  // native-Frida APIs requiring no JVM attachment, and the only JVM access
  // (Java.vm.tryGetEnv() below) happens lazily inside onEnter, at a point
  // where the VM is unavoidably already up (a JNI call is in flight). This
  // matters: a native, framework-level hook like this one wrapped in
  // Java.perform() instead would defer installation until the *target
  // app's own* classloader becomes available — exactly the ANR deadlock
  // this engine's init() avoids elsewhere via Java.performNow() instead of
  // Java.perform() for every other framework-level module (see the
  // rationale comment in rpc.exports.init()). If this module is called
  // from inside that same init()-awaited block, it must not reintroduce
  // that deadlock by wrapping itself in Java.perform().
  try {
    const listener = Interceptor.attach(targetAddr, {
      onEnter(args) {
        let className;
        try {
          const env = Java.vm.tryGetEnv();
          className = env.getClassName(args[1]);
        } catch (e) {
          return;
        }

        if (classFilter.size > 0 && !classFilter.has(className)) return;

        logD(`[RegisterNativesLog] >> ${className}`);

        const methodsPtr = ptr(args[2]);
        const methodCount = args[3].toInt32();
        let lastModName = null;

        for (let i = 0; i < methodCount; i++) {
          try {
            const base = methodsPtr.add(i * Process.pointerSize * 3);
            const name = base.readPointer().readCString();
            const sig = base.add(Process.pointerSize).readPointer().readCString();
            const fnPtr = base.add(Process.pointerSize * 2).readPointer();

            const mod = Process.findModuleByAddress(fnPtr);
            if (mod && mod.name !== lastModName) {
              logD(`[RegisterNativesLog]    [${mod.name}]`);
              lastModName = mod.name;
            }

            logD(mod
              ? `[RegisterNativesLog]    ${name}${sig} @0x${fnPtr.sub(mod.base).toString(16)}`
              : `[RegisterNativesLog]    ${name}${sig} @${fnPtr} (no module)`);
          } catch (itemErr) {
            logW(`[RegisterNativesLog] failed to read method entry ${i}: ${itemErr}`);
          }
        }
      }
    });
    appliedRegisterNativesListeners.push(listener);
    logI('[+] [RegisterNativesLog] RegisterNatives hooked');
  } catch (err) {
    logE('[!] [RegisterNativesLog] attach failed: ' + err);
  }
}

function revertRegisterNativesLog() {
  for (const listener of appliedRegisterNativesListeners) {
    try {
      listener.detach();
    } catch (err) {
      logW('[!] Failed to detach a RegisterNatives listener: ' + err);
    }
  }
  appliedRegisterNativesListeners.length = 0;
  logI('[*] RegisterNatives logging reverted.');
}

/**
 * SSL/TLS certificate-pinning bypass.
 *
 * Two independent layers, both executed in sequence:
 *
 *   Native layer — Flutter apps using dart:io, whose TLS verification
 *     runs in a statically-linked BoringSSL inside libflutter.so with
 *     no Java-layer involvement. The BoringSSL verify function is
 *     located without a fixed offset or byte signature (string-literal
 *     anchor scan -> ADRP cross-reference -> client/server pair ->
 *     prologue scan), then hooked via Interceptor.attach so its return
 *     value is forced to 1 ("verified"). ARM64-only; silently skipped
 *     on other architectures or when libflutter.so is not loaded.
 *
 *   Java/Kotlin layer — the standard Android TLS stack, OkHttp
 *     CertificatePinner, Android Network Security Config, and common
 *     third-party pinning libraries (TrustKit, Appmattus CT). Known
 *     targets are hooked by name; obfuscated (R8/ProGuard) classes are
 *     discovered at runtime by reflection over live X509TrustManager
 *     and HostnameVerifier instances (matched by signature shape, not
 *     by name), and by call-stack analysis anchored on the non-
 *     obfuscatable android.net.http.X509TrustManagerExtensions.
 *
 * Both layers install inside the framework-level Java.performNow()
 * block that init() awaits, so the bypass is active before any app
 * code — including a static initializer — can perform a TLS handshake.
 *
 * Gated by sslPinningBypassEnabled — see the module-level flag
 * declaration and its override in init().
 *
 * Out of scope (requires separate handling):
 *   - WebView traffic in a separate process.
 *   - Cronet / HTTP3 (org.chromium.net.X509Util).
 *   - Manually implemented certificate-hash comparison with no library.
 *   - Non-ARM64 Flutter builds.
 */
function applySslPinningBypass() {

    // ============================================================================
    // Module A - Native (Flutter / BoringSSL)
    // ============================================================================
    /**
     * Locates and hooks BoringSSL's certificate-chain verification function
     * inside libflutter.so without relying on a fixed offset or byte signature.
     *
     * Detection pipeline:
     *   1. Scan readable module memory for the string literals "ssl_client" and
     *      "ssl_server", which BoringSSL's ssl_crypto_x509_session_verify_cert_chain()
     *      passes to X509_STORE_CTX_set_default() (ssl/ssl_x509.cc). These are
     *      source-level constants and do not change across builds.
     *   2. Scan executable module memory for ADRP instructions (identified by
     *      ARM64 ISA encoding: high byte in {0x90, 0xB0, 0xD0, 0xF0}), then use
     *      Frida's disassembler to resolve each instruction's target page.
     *   3. Cross-reference resolved ADRP targets against the string locations
     *      from step 1.
     *   4. Pair the nearest "ssl_client" and "ssl_server" cross-references by
     *      address distance; the correct function contains both.
     *   5. From the lower address of the closest pair, scan backward for an
     *      ARM64 function prologue (`stp x29, x30, ...`) to locate the function
     *      entry point.
     *
     * Constraints:
     *   - ARM64 (arm64-v8a) only.
     *   - Only the single closest client/server pair is hooked by default
     *     (HOOK_TOP_N_PAIRS). Increase this if a target build requires trying
     *     additional candidate pairs.
     */
    var NativeBoringSSLBypass = (function () {
    
        var HOOK_TOP_N_PAIRS = 1;
        var MAX_PAIR_DISTANCE = 800;
        var PROLOGUE_SEARCH_WINDOW = 0x400;
    
        /** Converts an ASCII string to a space-separated hex byte pattern for Memory.scanSync. */
        function asciiToHexPattern(str) {
            var bytes = [];
            for (var i = 0; i < str.length; i++) {
                bytes.push(str.charCodeAt(i).toString(16).padStart(2, '0').toUpperCase());
            }
            return bytes.join(' ');
        }
    
        /** Returns memory ranges matching protectionFilter that overlap the given module. */
        function getRangesWithinModule(moduleInstance, protectionFilter) {
            var moduleStart = moduleInstance.base;
            var moduleEnd = moduleInstance.base.add(moduleInstance.size);
            var allRanges = Process.enumerateRanges(protectionFilter);
            return allRanges.filter(function (r) {
                var rangeStart = r.base;
                var rangeEnd = r.base.add(r.size);
                return rangeStart.compare(moduleEnd) < 0 && rangeEnd.compare(moduleStart) > 0;
            });
        }
    
        /** Returns the addresses of every occurrence of str within the given ranges. */
        function findStringAddresses(readableRanges, str) {
            var pattern = asciiToHexPattern(str);
            var found = [];
            readableRanges.forEach(function (range) {
                try {
                    var matches = Memory.scanSync(range.base, range.size, pattern);
                    matches.forEach(function (m) { found.push(m.address); });
                } catch (e) {}
            });
            return found;
        }
    
        /** Returns addresses of all 4-byte-aligned instructions whose encoding matches an ADRP opcode. */
        function findAdrpCandidates(execRanges) {
            var ADRP_HIGH_BYTES = [0x90, 0xB0, 0xD0, 0xF0];
            var candidates = [];
            execRanges.forEach(function (range) {
                var buf;
                try {
                    buf = range.base.readByteArray(range.size);
                } catch (e) {
                    return;
                }
                var view = new Uint8Array(buf);
                var len = view.length - (view.length % 4);
                for (var off = 0; off < len; off += 4) {
                    if (ADRP_HIGH_BYTES.indexOf(view[off + 3]) !== -1) {
                        candidates.push(range.base.add(off));
                    }
                }
            });
            return candidates;
        }
    
        /** Aligns an address down to its containing 4KB page. */
        function pageAlign(addr) {
            return addr.and(ptr('0xFFFFFFFFFFFFF000'));
        }
    
        /** Disassembles each ADRP candidate and returns those whose target page matches a target address. */
        function resolveMatchingAdrp(candidates, targetAddresses) {
            var targetPages = targetAddresses.map(pageAlign);
            var hits = [];
            candidates.forEach(function (addr) {
                var insn;
                try {
                    insn = Instruction.parse(addr);
                } catch (e) {
                    return;
                }
                if (!insn || insn.mnemonic !== 'adrp') return;
                try {
                    var immOperand = insn.operands[1];
                    if (!immOperand || immOperand.type !== 'imm') return;
                    var targetPage = ptr(immOperand.value.toString());
                    for (var i = 0; i < targetPages.length; i++) {
                        if (targetPages[i].equals(targetPage)) {
                            hits.push({ adrpAddress: addr, targetStringAddress: targetAddresses[i] });
                            break;
                        }
                    }
                } catch (e) {}
            });
            return hits;
        }
    
        /** Scans backward from adrpAddress for an ARM64 `stp x29, x30` prologue; returns its address or null. */
        function guessFunctionStart(adrpAddress, moduleInstance, maxBytesBack) {
            var searchStart = adrpAddress.sub(maxBytesBack);
            if (searchStart.compare(moduleInstance.base) < 0) {
                searchStart = moduleInstance.base;
            }
            var searchSize = adrpAddress.sub(searchStart).toInt32();
            if (searchSize <= 0) return null;
    
            var buf;
            try {
                buf = searchStart.readByteArray(searchSize);
            } catch (e) {
                return null;
            }
            var view = new Uint8Array(buf);
    
            var stpByteCandidates = [];
            for (var off = searchSize - 4; off >= 0; off -= 4) {
                if (view[off + 3] === 0xA9) {
                    stpByteCandidates.push(off);
                }
            }
    
            for (var i = 0; i < stpByteCandidates.length; i++) {
                var candidateAddr = searchStart.add(stpByteCandidates[i]);
                var insn;
                try {
                    insn = Instruction.parse(candidateAddr);
                } catch (e) {
                    continue;
                }
                if (!insn || insn.mnemonic !== 'stp') continue;
                try {
                    var opText = insn.opStr || '';
                    if (opText.indexOf('x29') !== -1 && opText.indexOf('x30') !== -1) {
                        return candidateAddr;
                    }
                } catch (e) {}
            }
            return null;
        }
    
        /**
         * Executes the discovery pipeline and installs the verification-bypass hook.
         * No-ops with a logged reason if the architecture is unsupported or
         * libflutter.so is not loaded.
         */
        function run() {
            if (Process.arch !== 'arm64') {
                logE('[-] [Native] Unsupported architecture: ' + Process.arch + ' (ARM64 required)');
                return;
            }
    
            try {
              var moduleName = 'libflutter.so';
              var flutterModule = Process.findModuleByName(moduleName);
              if (!flutterModule) {
                  logE('[-] [Native] ' + moduleName + ' not loaded in this process');
                  return;
              }
              logI('[*] [Native] ' + moduleName + ' base=' + flutterModule.base + ' size=' + flutterModule.size);
      
              var readableRanges = getRangesWithinModule(flutterModule, 'r--');
              var execRanges = getRangesWithinModule(flutterModule, 'r-x');
      
              var clientAddrs = findStringAddresses(readableRanges, 'ssl_client');
              var serverAddrs = findStringAddresses(readableRanges, 'ssl_server');
              logI('[*] [Native] string anchors: ssl_client=' + clientAddrs.length + ' ssl_server=' + serverAddrs.length);
      
              var allTargetAddrs = clientAddrs.concat(serverAddrs);
              if (allTargetAddrs.length === 0) {
                  logE('[-] [Native] no string anchors found, aborting');
                  return;
              }
      
              var candidates = findAdrpCandidates(execRanges);
              var hits = resolveMatchingAdrp(candidates, allTargetAddrs);
              logI('[*] [Native] adrp candidates=' + candidates.length + ' resolved cross-references=' + hits.length);
      
              if (hits.length === 0) {
                  logE('[-] [Native] no cross-references resolved, aborting');
                  return;
              }
      
              var clientHits = hits.filter(function (h) {
                  return clientAddrs.some(function (a) { return a.equals(h.targetStringAddress); });
              });
              var serverHits = hits.filter(function (h) {
                  return serverAddrs.some(function (a) { return a.equals(h.targetStringAddress); });
              });
      
              var pairs = [];
              clientHits.forEach(function (ch) {
                  serverHits.forEach(function (sh) {
                      var distance = Math.abs(ch.adrpAddress.sub(sh.adrpAddress).toInt32());
                      if (distance <= MAX_PAIR_DISTANCE) {
                          pairs.push({ clientAdrp: ch.adrpAddress, serverAdrp: sh.adrpAddress, distance: distance });
                      }
                  });
              });
              pairs.sort(function (a, b) { return a.distance - b.distance; });
              logI('[*] [Native] candidate pairs=' + pairs.length);
      
              if (pairs.length === 0) {
                  logE('[-] [Native] no pairs within MAX_PAIR_DISTANCE, aborting');
                  return;
              }
      
              var hookedCount = 0;
              for (var i = 0; i < Math.min(HOOK_TOP_N_PAIRS, pairs.length); i++) {
                  var pair = pairs[i];
                  var lowerAddr = pair.clientAdrp.compare(pair.serverAdrp) < 0 ? pair.clientAdrp : pair.serverAdrp;
                  var fnStart = guessFunctionStart(lowerAddr, flutterModule, PROLOGUE_SEARCH_WINDOW);
      
                  if (fnStart === null) {
                      logE('[-] [Native] pair #' + i + ': prologue not found, skipped');
                      continue;
                  }
      
                  logI('[+] [Native] pair #' + i + ': hooking ' + fnStart +
                      ' (offset=' + fnStart.sub(flutterModule.base) + ' distance=' + pair.distance + ')');
      
                  try {
                      var nativeListener = Interceptor.attach(fnStart, {
                          onEnter: function (args) {
                              logD('[*] [Native] verify() called');
                          },
                          onLeave: function (retval) {
                              retval.replace(1); // force "verified"
                          }
                      });
                      // appliedSslNativeAddresses stores the InvocationListener
                      // returned by Interceptor.attach (not a bare address) -
                      // detach() is the only way to undo an attach()-style hook,
                      // unlike the Java .implementation = null pattern used
                      // elsewhere in this engine.
                      appliedSslNativeAddresses.push(nativeListener);
                      hookedCount++;
                  } catch (e) {
                      logE('[-] [Native] attach failed: ' + e);
                  }
              }
      
              logI('[*] [Native] hooks installed=' + hookedCount);
              if (hookedCount === 0) {
                  logE('[!] [Native] native pinning bypass NOT active');
              }
            } catch (e) {
              logE('[-] [Native] run() threw: ' + e);
            }
        }
    
        return { run: run };
    })();
    
    
    // ============================================================================
    // Module B - Java/Kotlin
    // ============================================================================
    /**
     * Neutralizes certificate pinning across the Android Java/Kotlin TLS stack:
     * javax.net.ssl.* (SSLContext, TrustManagerFactory, HttpsURLConnection),
     * OkHttp's CertificatePinner, Android Network Security Config enforcement
     * classes, and third-party pinning libraries (TrustKit, Appmattus CT).
     *
     * In addition to known class/method targets, this module performs two forms
     * of runtime discovery so it continues to function against obfuscated
     * (R8/ProGuard) builds:
     *   - Reflection-based signature matching against all live TrustManager and
     *     HostnameVerifier instances (Section 9, 10).
     *   - Call-stack analysis anchored on the non-obfuscatable Android SDK class
     *     android.net.http.X509TrustManagerExtensions, used to locate and hook
     *     OkHttp's internal pin-check method regardless of its obfuscated name
     *     (Section 11).
     */
    var JavaLayerBypass = (function () {
    
        function run() {
            Java.perform(function () {
    
                // ------------------------------------------------------------------
                // Section 1: trust-all TrustManager and HostnameVerifier
                // ------------------------------------------------------------------
                var trustAll;
                try {
                    trustAll = Java.use('com.bypass.TrustAll').$new();
                } catch (e) {
                    var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
                    var TrustAllManager = Java.registerClass({
                        name: 'com.bypass.TrustAll',
                        implements: [X509TrustManager],
                        methods: {
                            checkClientTrusted: function (chain, authType) {},
                            checkServerTrusted: function (chain, authType) {},
                            getAcceptedIssuers: function () {
                                return Java.array('java.security.cert.X509Certificate', []);
                            }
                        }
                    });
                    trustAll = TrustAllManager.$new();
                }
    
                var trustAllVerifier;
                try {
                    trustAllVerifier = Java.use('com.bypass.TrustAllHostnameVerifier').$new();
                } catch (e) {
                    var HostnameVerifier = Java.use('javax.net.ssl.HostnameVerifier');
                    var TrustAllHostnameVerifier = Java.registerClass({
                        name: 'com.bypass.TrustAllHostnameVerifier',
                        implements: [HostnameVerifier],
                        methods: {
                            verify: function (hostname, session) {
                                return true;
                            }
                        }
                    });
                    trustAllVerifier = TrustAllHostnameVerifier.$new();
                }
    
                // ------------------------------------------------------------------
                // Section 2: shared trust-all SSLSocketFactory, used by Section 6
                // ------------------------------------------------------------------
                var TrustAllSSLSocketFactory = null;
                var SSLContext;
                try {
                    SSLContext = Java.use('javax.net.ssl.SSLContext');
                    var context = SSLContext.getInstance("TLS");
                    var initTrustArray = Java.array('javax.net.ssl.TrustManager', [trustAll]);
                    context.init(null, initTrustArray, null);
                    TrustAllSSLSocketFactory = context.getSocketFactory();
                } catch (e) {
                    logE('[-] [Java] trust-all SSLSocketFactory init failed: ' + e);
                }
    
                // ------------------------------------------------------------------
                // Section 3: SSLContext.init() - replaces the app-supplied
                // TrustManager array with the trust-all implementation.
                // ------------------------------------------------------------------
                try {
                    var sslContextInitTarget = SSLContext.init.overload(
                        '[Ljavax.net.ssl.KeyManager;',
                        '[Ljavax.net.ssl.TrustManager;',
                        'java.security.SecureRandom'
                    );
                    sslContextInitTarget.implementation = function (kms, tms, sr) {
                        logI('[+] [Java] SSLContext.init -> trust-all');
                        var trustArray = Java.array('javax.net.ssl.TrustManager', [trustAll]);
                        return this.init(kms, trustArray, sr);
                    };
                    appliedSslJavaHooks.push(sslContextInitTarget);
                } catch (e) {}

                // ------------------------------------------------------------------
                // Section 4: TrustManagerFactory.getTrustManagers() - covers apps
                // that request a system-provided TrustManager array instead of
                // constructing one directly.
                // ------------------------------------------------------------------
                try {
                    var TrustManagerFactory = Java.use('javax.net.ssl.TrustManagerFactory');
                    var getTrustManagersTarget = TrustManagerFactory.getTrustManagers;
                    getTrustManagersTarget.implementation = function () {
                        logI('[+] [Java] TrustManagerFactory.getTrustManagers -> trust-all');
                        return Java.array('javax.net.ssl.TrustManager', [trustAll]);
                    };
                    appliedSslJavaHooks.push(getTrustManagersTarget);
                } catch (e) {}

                // ------------------------------------------------------------------
                // Section 5: OkHttp CertificatePinner - neutralizes pin
                // registration at the builder, and replaces any already-built
                // pinner attached to an OkHttpClient.
                // ------------------------------------------------------------------
                try {
                    var CertificatePinnerBuilder = Java.use('okhttp3.CertificatePinner$Builder');
                    var pinnerAddTarget = CertificatePinnerBuilder.add.overload('java.lang.String', '[Ljava.lang.String;');
                    pinnerAddTarget.implementation = function (pattern, pins) {
                            logI('[+] [Java] CertificatePinner.Builder.add ignored: ' + pattern);
                            return this;
                        };
                    appliedSslJavaHooks.push(pinnerAddTarget);
                } catch (e) {
                    logE('[-] [Java] CertificatePinner.Builder hook failed: ' + e);
                }

                try {
                    var OkHttpBuilder = Java.use('okhttp3.OkHttpClient$Builder');
                    var emptyPinner = Java.use('okhttp3.CertificatePinner$Builder').$new().build();
                    var certificatePinnerTarget = OkHttpBuilder.certificatePinner.overload('okhttp3.CertificatePinner');
                    certificatePinnerTarget.implementation = function (original) {
                        logI('[+] [Java] OkHttpClient.Builder.certificatePinner -> empty pinner');
                        return this.certificatePinner(emptyPinner);
                    };
                    appliedSslJavaHooks.push(certificatePinnerTarget);
                } catch (e) {
                    logE('[-] [Java] OkHttpClient.Builder hook failed: ' + e);
                }

                // ------------------------------------------------------------------
                // Section 6: HttpsURLConnection - covers apps that set a socket
                // factory or hostname verifier directly, bypassing SSLContext.
                // ------------------------------------------------------------------
                try {
                    var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
                    var setDefaultSSLSocketFactoryTarget = HttpsURLConnection.setDefaultSSLSocketFactory;
                    setDefaultSSLSocketFactoryTarget.implementation = function (factory) {
                        if (TrustAllSSLSocketFactory) {
                            this.setDefaultSSLSocketFactory(TrustAllSSLSocketFactory);
                        }
                    };
                    appliedSslJavaHooks.push(setDefaultSSLSocketFactoryTarget);

                    var setDefaultHostnameVerifierTarget = HttpsURLConnection.setDefaultHostnameVerifier;
                    setDefaultHostnameVerifierTarget.implementation = function (verifier) {
                        this.setDefaultHostnameVerifier(trustAllVerifier);
                    };
                    appliedSslJavaHooks.push(setDefaultHostnameVerifierTarget);

                    var setSSLSocketFactoryTarget = HttpsURLConnection.setSSLSocketFactory;
                    setSSLSocketFactoryTarget.implementation = function (factory) {
                        if (TrustAllSSLSocketFactory) {
                            this.setSSLSocketFactory(TrustAllSSLSocketFactory);
                        }
                    };
                    appliedSslJavaHooks.push(setSSLSocketFactoryTarget);

                    var setHostnameVerifierTarget = HttpsURLConnection.setHostnameVerifier;
                    setHostnameVerifierTarget.implementation = function (verifier) {
                        this.setHostnameVerifier(trustAllVerifier);
                    };
                    appliedSslJavaHooks.push(setHostnameVerifierTarget);
                } catch (e) {
                    logE('[-] [Java] HttpsURLConnection hooks failed: ' + e);
                }
    
                // ------------------------------------------------------------------
                // Section 7: direct neutralization of system and library
                // TrustManager implementations that do not route through
                // SSLContext/TrustManagerFactory - required for Android Network
                // Security Config enforcement and libraries such as TrustKit and
                // Appmattus Certificate Transparency.
                // ------------------------------------------------------------------
                var ArrayList = Java.use('java.util.ArrayList');
                var trustManagers = [
                    'com.android.org.conscrypt.TrustManagerImpl',
                    'com.android.org.conscrypt.ConscryptX509TrustManager',
                    'android.security.net.config.NetworkSecurityTrustManager',
                    'android.security.net.config.RootTrustManager',
                    'com.datatheorem.android.trustkit.pinning.PinningTrustManager',
                    'com.appmattus.certificatetransparency.internal.verifier.CertificateTransparencyTrustManagerExtended',
                    'com.appmattus.certificatetransparency.internal.verifier.CertificateTransparencyTrustManagerBasic'
                ];
                trustManagers.forEach(function (name) {
                    try {
                        var cls = Java.use(name);
                        if (cls.checkServerTrusted) {
                            cls.checkServerTrusted.overloads.forEach(function (ov) {
                                ov.implementation = function () {
                                    if (ov.returnType.className !== 'void') {
                                        return ArrayList.$new();
                                    }
                                };
                                appliedSslJavaHooks.push(ov);
                            });
                            logI('[+] [Java] neutralized: ' + name);
                        }
                    } catch (e) {
                        // class not present in this app
                    }
                });

                // ------------------------------------------------------------------
                // Section 8: Appmattus Certificate Transparency - a check
                // independent of certificate pinning, bypassed separately.
                // ------------------------------------------------------------------
                try {
                    var CTHostnameVerifier = Java.use(
                        'com.appmattus.certificatetransparency.internal.verifier.CertificateTransparencyHostnameVerifier'
                    );
                    var ctVerifyTarget = CTHostnameVerifier.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession');
                    ctVerifyTarget.implementation = function (host, session) {
                            logI('[+] [Java] Appmattus CT hostname verifier bypassed');
                            return true;
                        };
                    appliedSslJavaHooks.push(ctVerifyTarget);
                } catch (e) {}
                try {
                    var CTInterceptor = Java.use(
                        'com.appmattus.certificatetransparency.internal.verifier.CertificateTransparencyInterceptor'
                    );
                    var ctInterceptTarget = CTInterceptor.intercept;
                    ctInterceptTarget.implementation = function (chain) {
                        logI('[+] [Java] Appmattus CT interceptor bypassed');
                        return chain.proceed(chain.request());
                    };
                    appliedSslJavaHooks.push(ctInterceptTarget);
                } catch (e) {}
    
                // ------------------------------------------------------------------
                // Section 9: reflection-based scan of live X509TrustManager
                // instances. Matches by method signature shape rather than by
                // name, so obfuscated (R8/ProGuard) classes are still located.
                // ------------------------------------------------------------------
                Java.choose('javax.net.ssl.X509TrustManager', {
                    onMatch: function (instance) {
                        try {
                            if (instance.$className === 'com.bypass.TrustAll') return;
    
                            var obfClass = Java.use(instance.$className);
                            var Method = Java.use('java.lang.reflect.Method');
                            var declaredMethods;
                            try {
                                declaredMethods = obfClass.class.getDeclaredMethods();
                            } catch (e) {
                                return;
                            }
    
                            declaredMethods.forEach(function (rawMethod) {
                                var method, methodName, paramTypes, returnTypeName;
                                try {
                                    method = Java.cast(rawMethod, Method);
                                    methodName = method.getName();
                                    paramTypes = method.getParameterTypes();
                                    returnTypeName = method.getReturnType().getName();
                                } catch (e) {
                                    return;
                                }
    
                                // (X509Certificate[], String[, Socket|SSLEngine]) -> void
                                // Matches checkClientTrusted/checkServerTrusted under both
                                // X509TrustManager (2-arg) and X509ExtendedTrustManager (3-arg).
                                var isCheckTrustedMatch = false;
                                try {
                                    var baseShape = paramTypes.length >= 2 &&
                                        paramTypes[0].isArray() &&
                                        paramTypes[0].getComponentType().getName() === 'java.security.cert.X509Certificate' &&
                                        paramTypes[1].getName() === 'java.lang.String' &&
                                        returnTypeName === 'void';
    
                                    if (baseShape && paramTypes.length === 2) {
                                        isCheckTrustedMatch = true;
                                    } else if (baseShape && paramTypes.length === 3) {
                                        var thirdParamName = paramTypes[2].getName();
                                        if (thirdParamName === 'java.net.Socket' ||
                                            thirdParamName === 'javax.net.ssl.SSLEngine') {
                                            isCheckTrustedMatch = true;
                                        }
                                    }
                                } catch (e) {
                                    isCheckTrustedMatch = false;
                                }
    
                                // () -> X509Certificate[] - matches getAcceptedIssuers()
                                var isAcceptedIssuersMatch = false;
                                try {
                                    isAcceptedIssuersMatch = paramTypes.length === 0 &&
                                        returnTypeName === '[Ljava.security.cert.X509Certificate;';
                                } catch (e) {
                                    isAcceptedIssuersMatch = false;
                                }
    
                                if (isCheckTrustedMatch) {
                                    try {
                                        obfClass[methodName].overloads.forEach(function (ov) {
                                            if (ov.returnType.className === 'void') {
                                                ov.implementation = function () {};
                                                appliedSslJavaHooks.push(ov);
                                            }
                                        });
                                        logI('[+] [Java] hooked ' + instance.$className + '.' + methodName + ' (checkTrusted)');
                                    } catch (hookErr) {}
                                }
    
                                if (isAcceptedIssuersMatch) {
                                    try {
                                        obfClass[methodName].overloads.forEach(function (ov) {
                                            ov.implementation = function () {
                                                return Java.array('java.security.cert.X509Certificate', []);
                                            };
                                            appliedSslJavaHooks.push(ov);
                                        });
                                        logI('[+] [Java] hooked ' + instance.$className + '.' + methodName + ' (getAcceptedIssuers)');
                                    } catch (hookErr) {}
                                }
                            });
                        } catch (e) {}
                    },
                    onComplete: function () {
                        logI('[+] [Java] X509TrustManager scan complete');
                    }
                });
    
                // ------------------------------------------------------------------
                // Section 10: reflection-based scan of live HostnameVerifier
                // instances, matched by the interface's sole abstract method
                // signature (String, SSLSession) -> boolean.
                // ------------------------------------------------------------------
                Java.choose('javax.net.ssl.HostnameVerifier', {
                    onMatch: function (instance) {
                        try {
                            if (instance.$className === 'com.bypass.TrustAllHostnameVerifier') return;
    
                            var obfClass = Java.use(instance.$className);
                            var Method = Java.use('java.lang.reflect.Method');
                            var declaredMethods;
                            try {
                                declaredMethods = obfClass.class.getDeclaredMethods();
                            } catch (e) {
                                return;
                            }
    
                            declaredMethods.forEach(function (rawMethod) {
                                var method, methodName, paramTypes, returnTypeName;
                                try {
                                    method = Java.cast(rawMethod, Method);
                                    methodName = method.getName();
                                    paramTypes = method.getParameterTypes();
                                    returnTypeName = method.getReturnType().getName();
                                } catch (e) {
                                    return;
                                }
    
                                if (paramTypes.length === 2 &&
                                    paramTypes[0].getName() === 'java.lang.String' &&
                                    paramTypes[1].getName() === 'javax.net.ssl.SSLSession' &&
                                    returnTypeName === 'boolean') {
                                    try {
                                        obfClass[methodName].overloads.forEach(function (ov) {
                                            ov.implementation = function () {
                                                return true;
                                            };
                                            appliedSslJavaHooks.push(ov);
                                        });
                                        logI('[+] [Java] hooked ' + instance.$className + '.' + methodName + ' (verify)');
                                    } catch (hookErr) {}
                                }
                            });
                        } catch (e) {}
                    },
                    onComplete: function () {
                        logI('[+] [Java] HostnameVerifier scan complete');
                    }
                });
    
                // ------------------------------------------------------------------
                // Section 11: runtime discovery of OkHttp's internal pin-check
                // method (check / check$okhttp), which is renamed on every
                // obfuscated build and therefore cannot be targeted by name.
                //
                // android.net.http.X509TrustManagerExtensions.checkServerTrusted()
                // is a fixed, non-obfuscatable Android SDK method that sits
                // adjacent to the real pin check in the call chain. Each time it
                // is invoked, the real call stack is walked and each non-framework
                // frame is inspected via reflection for one of two signatures:
                //
                //   (String, List)                 -> void   [older, Java]
                //   (String, <Kotlin lambda type>)  -> void   [modern, Kotlin;
                //       identified by the second parameter type exposing a
                //       zero-argument method literally named "invoke", which
                //       Kotlin's functional-interface contract prevents R8 from
                //       renaming]
                //
                // A matching frame is hooked as a no-op (void return, no
                // exception = pin accepted). Matches are memoized to avoid
                // re-walking the stack on every subsequent call. The original
                // checkServerTrusted() is always invoked first and its result
                // returned unchanged (or its exception re-thrown unchanged) -
                // this section only modifies the separately discovered method,
                // never X509TrustManagerExtensions itself.
                //
                // Known limitation: discovery only runs AFTER the original
                // checkServerTrusted() call returns (or throws). If the
                // TrustManager instance actually backing this call wasn't
                // already neutralized by Section 1-4/9 (e.g. it was
                // constructed after those installed, or reached through a
                // path those sections don't cover), the original call can
                // throw on a genuinely-untrusted interception-proxy
                // certificate - and since discovery happens after that call,
                // it would never run on that path at all, not merely be
                // delayed by one attempt. The original call is therefore
                // wrapped below so discovery still executes even when it
                // throws; the exception itself is still re-thrown afterward
                // so this hook's own behavior isn't otherwise changed.
                // ------------------------------------------------------------------
                try {
                    var X509TrustManagerExtensions = Java.use('android.net.http.X509TrustManagerExtensions');
                    var ReflectMethod = Java.use('java.lang.reflect.Method');
                    var alreadyHooked = {};
    
                    var skipPrefixes = ['android.', 'androidx.', 'java.', 'javax.',
                                         'kotlin.', 'kotlinx.', 'dalvik.', 'com.android.'];
    
                    X509TrustManagerExtensions.checkServerTrusted.overloads.forEach(function (ov) {
                        appliedSslJavaHooks.push(ov);
                        ov.implementation = function () {

                            // See "Known limitation" above: the original call
                            // is caught, not swallowed, so a throw here still
                            // lets discovery run below; the same error is
                            // re-thrown at the end so callers still observe
                            // this call's real outcome.
                            var args = Array.prototype.slice.call(arguments);
                            var result, callErr = null;
                            try {
                                result = this.checkServerTrusted.apply(this, args);
                            } catch (origErr) {
                                callErr = origErr;
                            }
    
                            try {
                                var exc = Java.use('java.lang.Exception').$new();
                                var stackElements = exc.getStackTrace();
    
                                for (var i = 0; i < stackElements.length; i++) {
                                    var className = stackElements[i].getClassName();
                                    var methodName = stackElements[i].getMethodName();
    
                                    var skip = false;
                                    for (var p = 0; p < skipPrefixes.length; p++) {
                                        if (className.indexOf(skipPrefixes[p]) === 0) { skip = true; break; }
                                    }
                                    if (skip) continue;
    
                                    var key = className + '.' + methodName;
                                    if (alreadyHooked[key]) continue;
    
                                    var cls;
                                    try {
                                        cls = Java.use(className);
                                    } catch (e) {
                                        continue;
                                    }
                                    if (!cls[methodName]) continue;
    
                                    cls[methodName].overloads.forEach(function (candidateOv) {
                                        try {
                                            var params = candidateOv.argumentTypes;
                                            var returnTypeName = candidateOv.returnType.className;
    
                                            if (params.length !== 2) return;
                                            if (params[0].className !== 'java.lang.String') return;
                                            if (returnTypeName !== 'void') return;
    
                                            var isCheckShape = false;
    
                                            if (params[1].className === 'java.util.List') {
                                                isCheckShape = true;
                                            } else {
                                                try {
                                                    var secondParamClass = Java.use(params[1].className).class;
                                                    var declared = secondParamClass.getMethods();
                                                    for (var m = 0; m < declared.length; m++) {
                                                        var dm = Java.cast(declared[m], ReflectMethod);
                                                        if (dm.getName() === 'invoke' &&
                                                            dm.getParameterTypes().length === 0) {
                                                            isCheckShape = true;
                                                            break;
                                                        }
                                                    }
                                                } catch (inner) {}
                                            }
    
                                            if (isCheckShape) {
                                                candidateOv.implementation = function () {
                                                    logI('[+] [Java] discovered and bypassed pin check: ' + className + '.' + methodName);
                                                };
                                                appliedSslJavaHooks.push(candidateOv);
                                                alreadyHooked[key] = true;
                                            }
                                        } catch (matchErr) {}
                                    });
                                }
                            } catch (walkErr) {}

                            if (callErr !== null) {
                                throw callErr;
                            }
                            return result;
                        };
                    });
    
                    logI('[+] [Java] OkHttp dynamic pin-check discovery installed');
                } catch (e) {
                    logE('[-] [Java] OkHttp dynamic pin-check discovery unavailable: ' + e);
                }
    
                logI('[*] [Java] all hooks installed');
            });
        }
    
        return { run: run };
    })();
    
    /**
     * Not covered by either module:
     *   - WebView traffic in a separate process (requires a second Frida
     *     session attached to the WebView provider process).
     *   - Cronet/HTTP3 (org.chromium.net.X509Util.verifyServerCertificates).
     *   - Manually implemented certificate-hash comparison with no library.
     *   - Non-ARM64 Flutter builds.
     */

    // ========================================================================
    // Entry point (original main())
    // ========================================================================
    var flutterPresent = false;
    try {
        flutterPresent = Process.findModuleByName('libflutter.so') !== null;
    } catch (e) {
        logW('[*] libflutter.so module check failed: ' + e);
    }
    
    if (flutterPresent) {
        logI('[*] libflutter.so detected, running native bypass');
        try {
            NativeBoringSSLBypass.run();
        } catch (e) {
            logE('[-] [Native] bypass failed: ' + e);
        }
    } else {
        logI('[*] libflutter.so not present, skipping native bypass');
    }
    
    logI('[*] running Java/Kotlin bypass');
    try {
        JavaLayerBypass.run();
    } catch (e) {
        logE('[-] [Java] bypass failed: ' + e);
    }
}

/**
 * Reverts applySslPinningBypass(): clears every Java-layer .implementation
 * override tracked in appliedSslJavaHooks (fixed-target hooks from
 * Sections 3-6/8, plus every dynamically-discovered overload pushed at
 * hook-install time from Sections 7/9/10/11 - trust manager neutralization,
 * the X509TrustManager/HostnameVerifier reflection scans, and OkHttp's
 * runtime-discovered pin-check method), then detaches the native BoringSSL
 * Interceptor.attach() listener(s) tracked in appliedSslNativeAddresses.
 *
 * Known limitation (shared with the rest of this engine's revert support):
 * Section 7's trust-manager neutralization and Sections 9/10's reflection
 * scans only hook classes/instances that exist AT THE TIME
 * applySslPinningBypass() ran. A TrustManager or HostnameVerifier class
 * loaded afterward was never hooked and is therefore not reverted either -
 * there is nothing to undo for it. This matches the one-shot, point-in-time
 * nature of the original discovery passes.
 */
function revertSslPinningBypass() {
  for (const target of appliedSslJavaHooks) {
    try {
      target.implementation = null;
    } catch (err) {
      logW('[!] Failed to revert an SSL-pinning Java hook: ' + err);
    }
  }
  appliedSslJavaHooks.length = 0;

  for (const listener of appliedSslNativeAddresses) {
    try {
      listener.detach();
    } catch (err) {
      logW('[!] Failed to detach an SSL-pinning native hook: ' + err);
    }
  }
  appliedSslNativeAddresses.length = 0;

  logI('[*] SSL pinning bypass reverted.');
}

/**
 * Resolves a boolean configuration flag, preferring the value
 * supplied in Gadget's parameters object over the module-level
 * default when present and correctly typed. If the key is present
 * but not a boolean, the type mismatch is logged and the module-level
 * default is retained, so a malformed configuration entry fails
 * safely and visibly rather than being silently ignored.
 */
function resolveBooleanFlag(parameters, key, currentDefault) {
  if (!parameters || !(key in parameters)) {
    return currentDefault;
  }
  const value = parameters[key];
  if (typeof value !== 'boolean') {
    logW(`[init] parameters.${key} expected boolean, got ${typeof value} — using default (${currentDefault})`);
    return currentDefault;
  }
  return value;
}

/**
 * Gadget lifecycle entry point. `parameters` is the JSON object
 * declared under interaction.parameters in libfrida-gadget.config.so,
 * supplied by Gadget itself when operating in Script interaction mode.
 * Each configuration flag falls back to its module-level default
 * (declared above) when the corresponding key is absent, which is
 * the mechanism by which the same defaults apply under Listen mode,
 * where no Gadget-supplied parameters exist.
 */
rpc.exports = {
  init(stage, parameters) {
    debugLoggingEnabled = resolveBooleanFlag(parameters, 'debugLog', debugLoggingEnabled);
    installerSpoofEnabled = resolveBooleanFlag(parameters, 'installerSpoofEnabled', installerSpoofEnabled);
    adbDevSettingsBypassEnabled = resolveBooleanFlag(parameters, 'adbDevSettingsBypassEnabled', adbDevSettingsBypassEnabled);
    mockLocationBypassEnabled = resolveBooleanFlag(parameters, 'mockLocationBypassEnabled', mockLocationBypassEnabled);
    autoTimeSpoofEnabled = resolveBooleanFlag(parameters, 'autoTimeSpoofEnabled', autoTimeSpoofEnabled);
    pairipLicenseBypassEnabled = resolveBooleanFlag(parameters, 'pairipLicenseBypassEnabled', pairipLicenseBypassEnabled);
    flagSecureBypassEnabled = resolveBooleanFlag(parameters, 'flagSecureBypassEnabled', flagSecureBypassEnabled);
    vpnProxyBypassEnabled = resolveBooleanFlag(parameters, 'vpnProxyBypassEnabled', vpnProxyBypassEnabled);
    geoRestrictionBypassEnabled = resolveBooleanFlag(parameters, 'geoRestrictionBypassEnabled', geoRestrictionBypassEnabled);
    geoSpoofValues = resolveMergedStringMap(parameters, 'geoSpoofValues', geoSpoofValues);
    localeSpoofEnabled = resolveBooleanFlag(parameters, 'localeSpoofEnabled', localeSpoofEnabled);
    localeSpoofValues = resolveMergedStringMap(parameters, 'localeSpoofValues', localeSpoofValues);
    suspiciousPackageSpoofEnabled = resolveBooleanFlag(parameters, 'suspiciousPackageSpoofEnabled', suspiciousPackageSpoofEnabled);
    suspiciousPackagesCustom = resolveStringArrayValue(parameters, 'suspiciousPackagesCustom', suspiciousPackagesCustom);
    installedPackageSpoofEnabled = resolveBooleanFlag(parameters, 'installedPackageSpoofEnabled', installedPackageSpoofEnabled);
    installedPackageSpoofValues = resolveNestedStringMap(parameters, 'installedPackageSpoofValues', installedPackageSpoofValues);
    deviceIdSpoofEnabled = resolveBooleanFlag(parameters, 'deviceIdSpoofEnabled', deviceIdSpoofEnabled);
    deviceIdSpoofUseRandom = resolveBooleanFlag(parameters, 'deviceIdSpoofUseRandom', deviceIdSpoofUseRandom);
    deviceIdSpoofValues = resolveMergedStringMap(parameters, 'deviceIdSpoofValues', deviceIdSpoofValues);
    buildPropSpoofEnabled = resolveBooleanFlag(parameters, 'buildPropSpoofEnabled', buildPropSpoofEnabled);
    buildPropSpoofValues = resolveMergedStringMap(parameters, 'buildPropSpoofValues', buildPropSpoofValues);
    systemPropertySpoofEnabled = resolveBooleanFlag(parameters, 'systemPropertySpoofEnabled', systemPropertySpoofEnabled);
    systemPropertySpoofValues = resolveOpenStringMap(parameters, 'systemPropertySpoofValues', systemPropertySpoofValues);
    hardwareFeatureSpoofEnabled = resolveBooleanFlag(parameters, 'hardwareFeatureSpoofEnabled', hardwareFeatureSpoofEnabled);
    spoofedHardwareFeatures = resolveStringArrayValue(parameters, 'spoofedHardwareFeatures', spoofedHardwareFeatures);
    contentProviderSpoofEnabled = resolveBooleanFlag(parameters, 'contentProviderSpoofEnabled', contentProviderSpoofEnabled);
    contentProviderSpoofValues = resolveNestedStringMap(parameters, 'contentProviderSpoofValues', contentProviderSpoofValues);
    javaHooksEnabled = resolveBooleanFlag(parameters, 'javaHooksEnabled', javaHooksEnabled);
    defaultJavaHooks = resolveJavaHooksArray(parameters, defaultJavaHooks);
    nativeHooksEnabled = resolveBooleanFlag(parameters, 'nativeHooksEnabled', nativeHooksEnabled);
    nativeHooks = resolveArrayValue(parameters, 'nativeHooks', nativeHooks);
    nativePatchesEnabled = resolveBooleanFlag(parameters, 'nativePatchesEnabled', nativePatchesEnabled);
    nativePatches = resolveArrayValue(parameters, 'nativePatches', nativePatches);
    registerNativesLogEnabled = resolveBooleanFlag(parameters, 'registerNativesLogEnabled', registerNativesLogEnabled);
    registerNativesLogClassFilter = resolveStringArrayValue(parameters, 'registerNativesLogClassFilter', registerNativesLogClassFilter);
    registerNativesLogLocator = resolveMergedStringMap(parameters, 'registerNativesLogLocator', registerNativesLogLocator);
    sslPinningBypassEnabled = resolveBooleanFlag(parameters, 'sslPinningBypassEnabled', sslPinningBypassEnabled);

    // Random values are computed once here, so that both
    // applyDeviceIdSpoof() (TelephonyManager/network methods) and the
    // ANDROID_ID entry contributed to the combined Settings key/value
    // map below observe the same generated identifiers.
    const effectiveDeviceIdValues = deviceIdSpoofUseRandom ? generateRandomDeviceIdValues() : deviceIdSpoofValues;

    logI(`[init] stage=${stage} debugLog=${debugLoggingEnabled} installerSpoofEnabled=${installerSpoofEnabled} adbDevSettingsBypassEnabled=${adbDevSettingsBypassEnabled} mockLocationBypassEnabled=${mockLocationBypassEnabled} autoTimeSpoofEnabled=${autoTimeSpoofEnabled} pairipLicenseBypassEnabled=${pairipLicenseBypassEnabled} flagSecureBypassEnabled=${flagSecureBypassEnabled} vpnProxyBypassEnabled=${vpnProxyBypassEnabled} geoRestrictionBypassEnabled=${geoRestrictionBypassEnabled} localeSpoofEnabled=${localeSpoofEnabled} suspiciousPackageSpoofEnabled=${suspiciousPackageSpoofEnabled} installedPackageSpoofEnabled=${installedPackageSpoofEnabled} deviceIdSpoofEnabled=${deviceIdSpoofEnabled} deviceIdSpoofUseRandom=${deviceIdSpoofUseRandom} buildPropSpoofEnabled=${buildPropSpoofEnabled} systemPropertySpoofEnabled=${systemPropertySpoofEnabled} hardwareFeatureSpoofEnabled=${hardwareFeatureSpoofEnabled} contentProviderSpoofEnabled=${contentProviderSpoofEnabled} javaHooksEnabled=${javaHooksEnabled} nativeHooksEnabled=${nativeHooksEnabled} nativePatchesEnabled=${nativePatchesEnabled} registerNativesLogEnabled=${registerNativesLogEnabled} sslPinningBypassEnabled=${sslPinningBypassEnabled}`);
    logD(`[init] parameters = ${JSON.stringify(parameters)}`);
    logD(`[init] effectiveDeviceIdValues = ${JSON.stringify(effectiveDeviceIdValues)}`);

    const secureSettingsKeyValues = {};
    if (adbDevSettingsBypassEnabled) {
      secureSettingsKeyValues['development_settings_enabled'] = '0';
      secureSettingsKeyValues['adb_enabled'] = '0';
    }
    if (mockLocationBypassEnabled) {
      secureSettingsKeyValues['mock_location'] = '0';
    }
    if (autoTimeSpoofEnabled) {
      secureSettingsKeyValues['auto_time'] = '1';
      secureSettingsKeyValues['auto_time_zone'] = '1';
    }
    if (deviceIdSpoofEnabled) {
      secureSettingsKeyValues['android_id'] = effectiveDeviceIdValues.androidId;
    }

    // The "settings" authority's map for applyContentProviderSpoof()
    // is the config's own contentProviderSpoofValues.settings entries
    // merged with secureSettingsKeyValues (built above from the
    // adbDevSettingsBypassEnabled/mockLocationBypassEnabled/
    // deviceIdSpoofEnabled flags) — the latter takes precedence for
    // any overlapping key, since those represent an explicit,
    // higher-level feature the user has already turned on, while any
    // additional keys unique to contentProviderSpoofValues.settings
    // are preserved. Every other authority is used as configured,
    // unmodified.
    const effectiveContentProviderValues = {};
    for (const [authority, kv] of Object.entries(contentProviderSpoofValues)) {
      effectiveContentProviderValues[authority] = Object.assign({}, kv);
    }
    effectiveContentProviderValues['settings'] = Object.assign(
      {},
      effectiveContentProviderValues['settings'] || {},
      secureSettingsKeyValues
    );

    // Every framework-level module (targeting always-preloaded
    // Android/bootclasspath classes, never the target app's own
    // classes) is installed inside this single Java.perform(), and
    // init() returns the Promise it resolves. Gadget's Script
    // interaction mode waits for init() to return, or for a returned
    // Promise to resolve, before releasing the host app's entrypoint —
    // returning this Promise is what guarantees every framework-level
    // hook here is active before any app code, including a static
    // initializer, runs. This closes a race condition where, without
    // it, an early static initializer could read a real value (e.g.
    // ANDROID_ID) before the corresponding hook was installed.
    //
    // The config-driven javaHooks array is deliberately NOT part of
    // this Promise: those hooks target the target app's OWN classes,
    // which may not be loaded yet when init() runs, and
    // applyHookWithRetry()'s backoff (up to 10 attempts at 500ms) can
    // legitimately take several seconds to resolve as those classes
    // load. Blocking the app's entrypoint on that would risk a
    // multi-second startup freeze or an ANR; it is therefore called
    // as a separate, non-blocking, best-effort operation instead.
    //
    // Gated by javaHooksEnabled rather than relying solely on an empty
    // defaultJavaHooks array to mean "off" — mirrors every other
    // config-driven module (nativeHooksEnabled, nativePatchesEnabled,
    // registerNativesLogEnabled) and lets a populated javaHooks array
    // be paused without clearing it.
    if (javaHooksEnabled) {
      applyAllJavaHooks(defaultJavaHooks);
    }

    return new Promise((resolve) => {
      // Java.performNow(), not Java.perform(): every module below
      // touches only framework/bootclasspath classes (Build,
      // TelephonyManager, PackageManager, Settings, NetworkInterface,
      // etc.), none of which require the host app's own classloader.
      // Java.perform() defers its callback until that classloader
      // becomes available — which happens only once app startup
      // proceeds — but app startup is exactly what this Promise is
      // blocking (Gadget holds the entrypoint until it resolves),
      // producing a deadlock that surfaces as an ANR ("failed to
      // complete startup"). performNow() executes immediately without
      // that dependency, which is the documented choice for callers
      // that don't need app-specific classes — see
      // https://frida.re/docs/javascript-api/#java (Java.performNow).
      Java.performNow(function () {
        // The entire block is wrapped in try/finally so that resolve()
        // is guaranteed to fire even if an unexpected exception escapes
        // every individual module's own internal try/catch — an
        // unresolved Promise here would leave Gadget waiting on init()
        // forever, which is a strictly worse outcome than the ANR this
        // performNow() change already fixed: the app would never start
        // at all, rather than merely stalling before eventually failing.
        try {
          if (Object.keys(secureSettingsKeyValues).length > 0) {
            applySecureSettingsSpoof(secureSettingsKeyValues);
          }

          if (installerSpoofEnabled) {
            applyInstallerSpoof();
          }

          if (mockLocationBypassEnabled) {
            applyMockLocationBypass();
          }

          if (pairipLicenseBypassEnabled) {
            applyPairipLicenseBypass();
          }

          if (flagSecureBypassEnabled) {
            applyFlagSecureBypass();
          }

          if (vpnProxyBypassEnabled) {
            applyVpnProxyDetectionBypass();
          }

          if (geoRestrictionBypassEnabled) {
            applyGeoRestrictionBypass();
          }

          if (localeSpoofEnabled) {
            applyLocaleSpoof();
          }

          if (suspiciousPackageSpoofEnabled) {
            applySuspiciousPackageSpoofing();
          }

          if (installedPackageSpoofEnabled) {
            applyInstalledPackageSpoof(installedPackageSpoofValues);
          }

          if (deviceIdSpoofEnabled) {
            applyDeviceIdSpoof(effectiveDeviceIdValues);
          }

          if (buildPropSpoofEnabled) {
            applyBuildPropSpoof(buildPropSpoofValues);
          }

          if (systemPropertySpoofEnabled) {
            applySystemPropertySpoof(systemPropertySpoofValues);
          }

          if (hardwareFeatureSpoofEnabled) {
            applyHardwareFeatureSpoof(spoofedHardwareFeatures);
          }

          if (contentProviderSpoofEnabled) {
            applyContentProviderSpoof(effectiveContentProviderValues);
          }

          if (nativeHooksEnabled) {
            applyNativeHooks(nativeHooks);
          }

          if (nativePatchesEnabled) {
            applyNativePatches(nativePatches);
          }

          if (registerNativesLogEnabled) {
            applyRegisterNativesLog(registerNativesLogClassFilter, registerNativesLogLocator);
          }

          // applySslPinningBypass() is intentionally last: its Interceptor.attach
          // trampoline on libflutter.so must be allocated AFTER nativePatches has
          // written its raw instruction bytes. If SSL installs first, a patch
          // whose target address is close to the SSL trampoline can overwrite it,
          // causing a SIGSEGV when the hooked function is next invoked. Ordering
          // is load-bearing — do not move this above nativePatches.
          if (sslPinningBypassEnabled) {
            applySslPinningBypass();
          }
        } catch (err) {
          logE('[init] Unexpected error during framework-level hook installation: ' + err);
        } finally {
          logI("[init] framework-level hook installation complete; releasing entrypoint.");
          resolve();
        }
      });
    });
  },
  dispose() {
    logI('[dispose] reverting hooks');
    // revertAllHooks() is self-gating — it only iterates appliedHooks,
    // which is empty whenever javaHooksEnabled was never on — so this
    // check is not load-bearing. It is here anyway to mirror every
    // other module's apply/revert pairing (see nativeHooksEnabled
    // below) rather than being the one silent exception.
    if (javaHooksEnabled) {
      revertAllHooks();
    }
    // Mirrors the gate init() uses to decide whether
    // applySecureSettingsSpoof() was ever called: secureSettingsKeyValues
    // is only non-empty (and the apply only happens) when at least one of
    // these four flags is set, so the revert is gated the same way rather
    // than on a single flag.
    if (adbDevSettingsBypassEnabled || mockLocationBypassEnabled || autoTimeSpoofEnabled || deviceIdSpoofEnabled) {
      Java.performNow(function () {
        revertSecureSettingsSpoof();
      });
    }
    if (installerSpoofEnabled) {
      Java.performNow(function () {
        revertInstallerSpoof();
      });
    }
    if (mockLocationBypassEnabled) {
      Java.performNow(function () {
        revertMockLocationBypass();
      });
    }
    if (pairipLicenseBypassEnabled) {
      Java.performNow(function () {
        revertPairipLicenseBypass();
      });
    }
    if (flagSecureBypassEnabled) {
      Java.performNow(function () {
        revertFlagSecureBypass();
      });
    }
    if (vpnProxyBypassEnabled) {
      Java.performNow(function () {
        revertVpnProxyDetectionBypass();
      });
    }
    if (geoRestrictionBypassEnabled) {
      Java.performNow(function () {
        revertGeoRestrictionBypass();
      });
    }
    if (localeSpoofEnabled) {
      Java.performNow(function () {
        revertLocaleSpoof();
      });
    }
    if (suspiciousPackageSpoofEnabled) {
      Java.performNow(function () {
        revertSuspiciousPackageSpoofing();
      });
    }
    if (installedPackageSpoofEnabled) {
      Java.performNow(function () {
        revertInstalledPackageSpoof();
      });
    }
    if (buildPropSpoofEnabled) {
      Java.performNow(function () {
        revertBuildPropSpoof();
      });
    }
    if (systemPropertySpoofEnabled) {
      Java.performNow(function () {
        revertSystemPropertySpoof();
      });
    }
    if (deviceIdSpoofEnabled) {
      Java.performNow(function () {
        revertDeviceIdSpoof();
      });
    }
    if (hardwareFeatureSpoofEnabled) {
      Java.performNow(function () {
        revertHardwareFeatureSpoof();
      });
    }
    if (contentProviderSpoofEnabled) {
      Java.performNow(function () {
        revertContentProviderSpoof();
      });
    }
    if (nativeHooksEnabled) {
      revertNativeHooks();
    }
    if (nativePatchesEnabled) {
      revertNativePatches();
    }
    if (registerNativesLogEnabled) {
      revertRegisterNativesLog();
    }
    // Reverted last, mirroring applySslPinningBypass() being applied last
    // in init() (see the ordering comment there re: the native trampoline
    // vs. nativePatches). Wrapped in Java.performNow() for the Java-layer
    // hook clears; the native BoringSSL listener detach() inside
    // revertSslPinningBypass() does not itself require a JVM context, but
    // sharing one callback keeps this consistent with every other revert
    // here and avoids a second, redundant Java.performNow() call.
    if (sslPinningBypassEnabled) {
      Java.performNow(function () {
        revertSslPinningBypass();
      });
    }
  }
};