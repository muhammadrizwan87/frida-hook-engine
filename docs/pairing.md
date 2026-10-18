# Module Pairing

Every module is independent. No module *requires* another to be enabled
in order to function. The engine does not enforce combinations, and no
combination is guaranteed to be more correct than any other.

This page documents two things that look like pairing but are not
dependencies:

1. **Automatic value contributions** — keys some modules push into
   `contentProviderSpoofEnabled` at apply time, so you do not have to
   list them twice.
2. **Environment-dependent groupings** — combinations that are commonly
   useful together because of a specific device or target property, not
   because of any inter-module dependency.

Read this page as a map of *interactions*, not a set of requirements.

---

## Independence

Each of the following pairs is often assumed to be a dependency. It is
not. Enable each module only when the target's own behavior calls for it.

| Modules | Relationship |
|---|---|
| `sslPinningBypassEnabled` + `vpnProxyBypassEnabled` | Independent. SSL bypass covers certificate verification; VPN/proxy bypass covers a target that refuses to run under a VPN or detects proxy configuration. Common during MITM work, but enabling one does not require the other. |
| `pairipLicenseBypassEnabled` + `installedPackageSpoofEnabled` | Independent. See [Environment-dependent groupings](#environment-dependent-groupings) below. |
| `pairipLicenseBypassEnabled` + `installerSpoofEnabled` | Independent. PairIP's own check and a target's own installer-source check are separate code paths. Enable `installerSpoofEnabled` only if the target's own code checks installer source, independent of PairIP. |
| `installedPackageSpoofEnabled` + `installerSpoofEnabled` | Independent. Adding a package to the target's view of installed apps is separate from reporting a specific package as the installer. |
| `adbDevSettingsBypassEnabled` + `contentProviderSpoofEnabled` | Independent, but see [Automatic value contributions](#automatic-value-contributions). |
| `mockLocationBypassEnabled` + `contentProviderSpoofEnabled` | Independent, but see [Automatic value contributions](#automatic-value-contributions). |
| `autoTimeSpoofEnabled` + `contentProviderSpoofEnabled` | Independent, but see [Automatic value contributions](#automatic-value-contributions). |
| `deviceIdSpoofEnabled` + `contentProviderSpoofEnabled` | Independent, but see [Automatic value contributions](#automatic-value-contributions). |
| `geoRestrictionBypassEnabled` + `localeSpoofEnabled` | Independent. Geo spoofs carrier and network identity; locale spoofs displayed language, region, and formatting. Enable each only when the target reads the corresponding surface. |
| `buildPropSpoofEnabled` + `systemPropertySpoofEnabled` | Independent. The two cover different reads — see [Build-Prop and System-Property](#build-prop-and-system-property) below. |
| `suspiciousPackageSpoofEnabled` + `installedPackageSpoofEnabled` | Independent, and inverses. The first removes packages from the target's view; the second adds them. They can run together, but a package listed in both is a configuration mistake. |

---

## Automatic value contributions

`contentProviderSpoofEnabled` is the one module that consumes keys from
other modules at apply time. When it is enabled, its `settings` authority
map is merged with keys derived from four other flags, so you do not need
to list those keys twice.

| Contributor flag | Adds key(s) to `settings` |
|---|---|
| `adbDevSettingsBypassEnabled` | `development_settings_enabled`, `adb_enabled` |
| `mockLocationBypassEnabled` | `mock_location` |
| `autoTimeSpoofEnabled` | `auto_time`, `auto_time_zone` |
| `deviceIdSpoofEnabled` | `android_id` |

Two rules:

- The contributor flag must be `true` for its keys to be contributed.
  A contributor flag set to `false` contributes nothing.
- On overlap between a key listed in
  `contentProviderSpoofValues.settings` and a key contributed by one of
  the flags above, the contributor flag wins. The higher-level flag is
  treated as the authoritative source for that key.

Every authority other than `settings` is used exactly as configured in
`contentProviderSpoofValues`, with no merging.

**Why this matters.** A target that reads `content://settings/...`
directly bypasses the convenience `Settings.Secure` / `Settings.Global`
methods the contributor modules hook. Enabling
`contentProviderSpoofEnabled` alongside a contributor flag gives the
same spoofed value on both paths. Enabling only the contributor flag
leaves the ContentResolver path unspoofed.

---

## Environment-dependent groupings

The combinations below are commonly useful together — not because of any
dependency between the modules, but because of a specific device or
target property. Enable only the ones that apply.

### PairIP on a device without Play Store
> NOTE: not a paid/commercial license bypass. This only unblocks a   
> free app's client-side PairIP check inside a virtualized/emulated   
> research environment.

`pairipLicenseBypassEnabled` neutralizes the PairIP license-check client.
Some PairIP-Licensed apps additionally check for Play Store presence as
a separate code path.

- **Device already has Play Store / GMS / GSF installed:** only
  `pairipLicenseBypassEnabled` is needed.
- **Device does not have Play Store / GMS / GSF installed:** enable both
  `pairipLicenseBypassEnabled` and `installedPackageSpoofEnabled` to
  cover both the license-check client and the presence check.

`installerSpoofEnabled` is orthogonal. Enable it only if the target's
own code — separate from PairIP — checks installer source.

```jsonc
"pairipLicenseBypassEnabled": true,
"installedPackageSpoofEnabled": true,
"installedPackageSpoofValues": {
  "com.android.vending": { "isSystem": "true" },
  "com.google.android.gms": { "isSystem": "true" },
  "com.google.android.gsf": { "isSystem": "true" }
}
```

### ContentResolver-direct settings reads

If the target queries `content://settings/...` directly instead of
calling the convenience `Settings.Secure` / `Settings.Global` methods,
the corresponding Settings-level module alone does not cover it. Enable
`contentProviderSpoofEnabled` alongside the contributor flag(s) to
cover both paths.

| Settings-level flag enabled | Add `contentProviderSpoofEnabled` when... |
|---|---|
| `adbDevSettingsBypassEnabled` | The target also reads settings via ContentResolver |
| `mockLocationBypassEnabled` | The target also reads `mock_location` via ContentResolver |
| `autoTimeSpoofEnabled` | The target also reads `auto_time` / `auto_time_zone` via ContentResolver |
| `deviceIdSpoofEnabled` | The target also reads `android_id` via ContentResolver |

Both the settings-level module and `contentProviderSpoofEnabled` may be
enabled simultaneously with no conflict — the module handles the merge
internally.

### Region-locked content

`geoRestrictionBypassEnabled` spoofs carrier and network identity.
`localeSpoofEnabled` spoofs displayed language, region, and formatting.
A target that gates content on carrier/PLMN reads the first; a target
that gates on locale reads the second.

- For a target that only checks carrier/PLMN: enable
  `geoRestrictionBypassEnabled`.
- For a target that only checks locale: enable `localeSpoofEnabled`.
- For a target that checks both: enable both.

Neither requires the other. See the
[Locale / Timezone Spoofing](modules.md#locale--timezone-spoofing)
runtime-impact section for what the locale module changes.

---

### Emulator detection bypass

A target that runs emulator checks reads from several independent
surfaces. No module covers more than one surface, and no module depends
on another — enable only the ones matching what the target actually
reads.

| Surface read | Module |
|---|---|
| `android.os.Build.*` fields (`MANUFACTURER`, `MODEL`, `FINGERPRINT`, …) | `buildPropSpoofEnabled` |
| Raw `ro.*` / `persist.*` / `qemu.*` properties (bootloader-lock state, emulator artifacts) | `systemPropertySpoofEnabled` |
| IMEI / MEID / MAC / advertising ID / ANDROID_ID | `deviceIdSpoofEnabled` |
| `PackageManager.hasSystemFeature()` checks | `hardwareFeatureSpoofEnabled` |

A target checking one surface is unaffected by the others. A target
checking several surfaces needs the corresponding modules — a partial
match leaves the other surfaces unspoofed.

`deviceIdSpoofUseRandom` is a modifier of `deviceIdSpoofEnabled`, not a
module of its own — set it to `true` for fresh identifiers on each app
launch, or leave it `false` to use the fixed profile in
`deviceIdSpoofValues`.

Example config covering all four surfaces, with random device
identifiers:

```jsonc
"buildPropSpoofEnabled": true,
"systemPropertySpoofEnabled": true,
"deviceIdSpoofEnabled": true,
"deviceIdSpoofUseRandom": true,
"hardwareFeatureSpoofEnabled": true
```
---

## Build-Prop and System-Property

`buildPropSpoofEnabled` and `systemPropertySpoofEnabled` are often
described as a single emulator-bypass surface. They cover two
independently-implemented reads.

`android.os.Build`'s fields are populated from `SystemProperties` **once**,
at the class-initialization of `android.os.Build`. After that point,
`Build.MANUFACTURER` and similar are plain static fields — reading
`SystemProperties.get("ro.product.manufacturer")` returns the property
store's value, not `Build`'s field.

- `buildPropSpoofEnabled` mutates the already-initialized `Build.*`
  fields directly. Every subsequent reader of `Build.MANUFACTURER`
  observes the spoofed value.
- `systemPropertySpoofEnabled` intercepts `SystemProperties.get()`. Every
  caller that reads a raw property — directly or through another
  framework class that reads properties — observes the spoofed value.

Neither module overwrites the other's coverage. A target that checks
`Build.MANUFACTURER` needs `buildPropSpoofEnabled`. A target that reads
`ro.product.manufacturer` or `ro.boot.flash.locked` directly needs
`systemPropertySpoofEnabled`. A target that does both needs both.

Enable each based on what the target actually reads — not as a set.

---

## Related pages

- [Modules](modules.md) — per-module description and mini config
- [Configuration](configuration.md) — full parameter reference and config model
- [Module Limits](limits.md) — open vs. closed value maps and platform boundaries
- [Architecture](architecture.md) — two-phase hook installation and ordering rules