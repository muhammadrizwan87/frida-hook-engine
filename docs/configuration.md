# Configuration

The engine exposes a single config surface — a flat set of named
parameters. This page covers how that surface works and lists every
parameter.

For per-module details, see [Modules](modules.md). For dependency and
value-contribution rules between modules, see [Module Pairing](pairing.md).

---

## Config model

### Three files, one config surface

The engine ships as three coordinated files:

| File | Purpose | Who edits it |
|---|---|---|
| `engine.js` | Source script, plain JavaScript | Advanced users, contributors |
| `agent.js` | Pre-compiled bundle for Gadget | Maintainers only |
| `config.json` | Runtime parameters for the agent | End users |

Every parameter has a source-level default declared at the top of
`engine.js`. `config.json` overrides those defaults at runtime. A user
who never edits `engine.js` still gets a fully working engine — only
`config.json` needs attention.

### Where the config applies

The `config.json` file applies only to **Gadget Script interaction
mode**. The other two deployment modes have no config file:

| Mode | How parameters are supplied |
|---|---|
| **Gadget — Script** | `config.json` → `interaction.parameters` |
| **Frida CLI — attach / spawn** | None — call `rpc.exports.init()` from the REPL; source-level defaults apply |
| **Gadget — Listen** | Passed to `rpc.exports.init()` from a live controller |

For CLI attach / spawn, edit the flags at the top of `engine.js` to
change behavior. For Listen mode, the controller calls
`rpc.exports.init(stage, parameters)` with a parameters object matching
the same schema as `interaction.parameters`.

In Gadget Script mode, `init()` is called automatically. In the other
three modes, call it manually. The REPL syntax, `stage` argument, and
`dispose()` are documented in
[Advanced Usage → Runtime control](advanced-usage.md#runtime-control).

### Priority rule

```
config.json value (if key present)
  overrides
engine.js source-level default
  always present as fallback
```

Three cases:

| Case | Behavior |
|---|---|
| Key present and correctly typed | Config value used |
| Key present, wrong type | Warning logged, source default used |
| Key absent | Source default used |

A malformed config never breaks the engine — every resolver falls back
to the source default and logs a warning identifying the key and
expected type.

### Flag / value relationship

Module flags end in `Enabled` (e.g. `sslPinningBypassEnabled`). Some
flags have a companion value object (e.g. `geoSpoofValues`).

**A value object only takes effect when its companion flag is `true`.**
With the flag `false`, the value object is ignored entirely and the
module does not run. Setting `geoSpoofValues` while
`geoRestrictionBypassEnabled` is `false` has no effect.

---

## Parameter reference

Every parameter is optional. Missing parameters fall back to their
source-level defaults; wrong-typed parameters are logged and ignored.

### Module flags

| Parameter | Type | Default | Module |
|---|---|---|---|
| `debugLog` | boolean | `false` | Engine logging |
| `installerSpoofEnabled` | boolean | `false` | Installer-source spoofing |
| `adbDevSettingsBypassEnabled` | boolean | `false` | ADB / Developer Options bypass |
| `mockLocationBypassEnabled` | boolean | `false` | Mock-location bypass |
| `autoTimeSpoofEnabled` | boolean | `false` | Auto-time / auto-timezone spoofing |
| `pairipLicenseBypassEnabled` | boolean | `false` | PairIP license NOP |
| `flagSecureBypassEnabled` | boolean | `false` | FLAG_SECURE bypass |
| `vpnProxyBypassEnabled` | boolean | `false` | VPN / proxy bypass |
| `sslPinningBypassEnabled` | boolean | `false` | SSL pinning bypass *(beta)* |
| `geoRestrictionBypassEnabled` | boolean | `false` | Geo / carrier spoofing |
| `localeSpoofEnabled` | boolean | `false` | Locale / timezone spoofing |
| `suspiciousPackageSpoofEnabled` | boolean | `false` | Suspicious-package hiding |
| `installedPackageSpoofEnabled` | boolean | `false` | Installed-package spoofing |
| `deviceIdSpoofEnabled` | boolean | `false` | Device-ID spoofing |
| `buildPropSpoofEnabled` | boolean | `false` | Build-prop spoofing |
| `systemPropertySpoofEnabled` | boolean | `false` | System-property spoofing |
| `hardwareFeatureSpoofEnabled` | boolean | `false` | Hardware-feature spoofing |
| `contentProviderSpoofEnabled` | boolean | `false` | ContentProvider spoofing |
| `javaHooksEnabled` | boolean | `false` | Config-driven Java hooking |
| `nativeHooksEnabled` | boolean | `false` | Native hooking |
| `nativePatchesEnabled` | boolean | `false` | Native patching |
| `registerNativesLogEnabled` | boolean | `false` | RegisterNatives discovery/logging |

### Value objects

| Parameter | Type | Default | Companion flag |
|---|---|---|---|
| `geoSpoofValues` | object | see [Modules](modules.md) | `geoRestrictionBypassEnabled` |
| `localeSpoofValues` | object | see [Modules](modules.md) | `localeSpoofEnabled` |
| `suspiciousPackagesCustom` | array\<string\> | see [Modules](modules.md) | `suspiciousPackageSpoofEnabled` |
| `installedPackageSpoofValues` | object | see [Modules](modules.md) | `installedPackageSpoofEnabled` |
| `deviceIdSpoofUseRandom` | boolean | `false` | `deviceIdSpoofEnabled` |
| `deviceIdSpoofValues` | object | see [Modules](modules.md) | `deviceIdSpoofEnabled` (when `deviceIdSpoofUseRandom` is `false`) |
| `buildPropSpoofValues` | object | see [Modules](modules.md) | `buildPropSpoofEnabled` |
| `systemPropertySpoofValues` | object | see [Modules](modules.md) | `systemPropertySpoofEnabled` |
| `spoofedHardwareFeatures` | array\<string\> | see [Modules](modules.md) | `hardwareFeatureSpoofEnabled` |
| `contentProviderSpoofValues` | object | see [Modules](modules.md) | `contentProviderSpoofEnabled` |
| `javaHooks` | array\<object\> | `[]` | `javaHooksEnabled` |
| `nativeHooks` | array\<object\> | `[]` | `nativeHooksEnabled` |
| `nativePatches` | array\<object\> | `[]` | `nativePatchesEnabled` |
| `registerNativesLogClassFilter` | array\<string\> | `[]` | `registerNativesLogEnabled` |
| `registerNativesLogLocator` | object | `{ symbolName: "", offset: "" }` | `registerNativesLogEnabled` |

---

## Value object schemas

Value objects follow one of four shapes. Each module documents which
shape it uses.

| Schema | Modules | Shape |
|---|---|---|
| **Closed-key flat map** | `geoSpoofValues`, `localeSpoofValues`, `buildPropSpoofValues`, `deviceIdSpoofValues`, `registerNativesLogLocator` | `{ key: string }` — fixed key set |
| **Open-key flat map** | `systemPropertySpoofValues` | `{ key: string }` — any key accepted |
| **Nested map** | `contentProviderSpoofValues`, `installedPackageSpoofValues` | `{ outer: { inner: string } }` |
| **String array** | `suspiciousPackagesCustom`, `spoofedHardwareFeatures` | `[string, ...]` |

### Closed-key flat maps

Only the declared keys are accepted. An unrecognized key is logged and
ignored; a recognized key with a non-string value is logged and its
default is retained. Suited to value maps where the set of valid keys is
fixed — for example, `buildPropSpoofValues`, whose keys correspond
exactly to the `android.os.Build` fields the engine writes.

### Open-key flat maps

Any string-valued key is accepted, in addition to the declared defaults.
Suited to value maps where the key space is inherently unbounded — for
example, `systemPropertySpoofValues`, where any `ro.*`, `persist.*`, or
`qemu.*` property name is a valid key.

### Nested maps

Two-level `{ outer: { inner: string } }` shape, with both levels open.
An outer entry that isn't an object is rejected with a warning; a
non-string inner value is rejected with a warning and that key is
skipped. Used by `contentProviderSpoofValues` (outer key = authority)
and `installedPackageSpoofValues` (outer key = package name).

### String arrays

An array in which every element is a string. A non-array or an array
containing a non-string element is rejected with a warning and the
source default is retained.

---

## Type coercion rules

Resolvers are strict about type. A wrong-typed value never silently
coerces — it is logged and the source default is used.

| Declared type | Wrong-type behavior |
|---|---|
| `boolean` | Logs `expected boolean`, uses default |
| `string` | Logs `expected string`, uses default |
| `object` | Logs `expected object`, uses defaults |
| `array<string>` | Logs `expected an array of strings`, uses default |
| `array<object>` | Logs `expected an array`; malformed entries are caught per-item |

`array<object>` resolvers (used by `nativeHooks`, `nativePatches`, and
`javaHooks`) validate array-ness at the resolver level and defer
per-entry validation to the apply function. A malformed entry is
rejected individually without affecting other entries.

---

## Minimal config

A complete `config.json` enabling one module:

```jsonc
{
  "interaction": {
    "type": "script",
    "path": "libfrida-gadget.script.so",
    "on_change": "reload",
    "parameters": {
      "sslPinningBypassEnabled": true
    }
  }
}
```

Every other parameter falls back to its source default. You only list
what you change.

---

## Related pages

- [Modules](modules.md) — per-module description and mini config
- [Module Pairing](pairing.md) — which modules depend on or feed into others
- [Module Limits](limits.md) — open vs. closed value maps and platform boundaries
- [Installation](installation.md) — setup for container, repack, and CLI modes