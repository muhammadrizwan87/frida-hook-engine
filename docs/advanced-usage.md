# Advanced Usage

Patterns for using the config-driven hooking modules: `javaHooks`,
`nativeHooks`, and `nativePatches`. Each section states the config, the
runtime behavior, and any edge cases that affect what the target sees.

For module-adding conventions when forking the engine itself, see
[Architecture → Adding a module](architecture.md#adding-a-module).

---

## Java hooks

The config-driven Java hooking module is gated by `javaHooksEnabled`.
When `true`, the `javaHooks` array's entries install; when `false` (the
default), the array is ignored.

Each entry targets one method. When the method has multiple overloads,
`argTypes` selects a specific one to hook. Omitting `argTypes` hooks
every overload with the same implementation — see
[Multi-overload methods](#multi-overload-methods) below.
### Observe only

Original runs unmodified. Useful for logging what the target does
without changing its behavior.

```jsonc
"javaHooksEnabled": true,
"javaHooks": [
  {
    "className": "com.example.Network",
    "methodName": "request",
    "argTypes": ["java.lang.String"],
    "returnType": "java.lang.String",
    "onCall": { "logArgs": true, "logReturn": true }
  }
]
```

### Silence a void method

The original is not called. No return value is produced.

```jsonc
"javaHooksEnabled": true,
"javaHooks": [
  {
    "className": "com.example.Logger",
    "methodName": "writeLog",
    "argTypes": ["java.lang.String"],
    "returnType": "void",
    "onCall": { "nop": true }
  }
]
```

`nop` on a void method needs no `forceReturn`. The JNI boundary expects
`undefined` for a void return and `nop` produces exactly that.

### Silence a non-void method

The original is not called, and a specific return value is supplied.

```jsonc
"javaHooksEnabled": true,
"javaHooks": [
  {
    "className": "com.example.RootChecker",
    "methodName": "isDeviceRooted",
    "returnType": "boolean",
    "onCall": { "nop": true, "forceReturn": false }
  }
]
```

`nop` + non-void without `forceReturn` returns `undefined` at the JNI
boundary. For a primitive return type that is usually wrong — Java will
see `0` / `false`, or the VM may raise a JNI type error. Always supply
`forceReturn` when `nop` is set on a non-void method.

### Force return without skipping the original

The original runs (its side effects happen), but the caller observes the
forced return value.

```jsonc
"javaHooksEnabled": true,
"javaHooks": [
  {
    "className": "com.example.AccountManager",
    "methodName": "getBalance",
    "argTypes": ["int"],
    "returnType": "double",
    "onCall": { "logReturn": true, "forceReturn": 999999.99 }
  }
]
```

Use this when the target's real work must still happen — for example,
to keep a database write or a network call — but its return value must
be overridden.

### Modify one argument

The original runs and sees the modified argument. No return override.

```jsonc
"javaHooksEnabled": true,
"javaHooks": [
  {
    "className": "com.example.LocationProvider",
    "methodName": "setAccuracy",
    "argTypes": ["int"],
    "returnType": "void",
    "onCall": {
      "logArgs": true,
      "modifyArgs": { "0": 5 }
    }
  }
]
```

`modifyArgs` indices are 0-based, expressed as strings. The value is
coerced through `argTypes[idx]` — a `"boolean"` argument is coerced to a
JS boolean, a `"long"` argument is coerced to a Java `long`, and so on.

### Modify one argument and force the return

Combines both. Multi-overload methods require `argTypes` to select the
right overload.

```jsonc
"javaHooksEnabled": true,
"javaHooks": [
  {
    "className": "com.example.LicenseManager",
    "methodName": "isValidLicense",
    "argTypes": ["java.lang.String", "int"],
    "returnType": "boolean",
    "onCall": {
      "logArgs": true,
      "modifyArgs": { "1": 9999 },
      "forceReturn": true
    }
  }
]
```

### Multiple hooks in one array

The `javaHooks` array accepts multiple entries — one per method or per
overload. All entries install in the same deferred pass.

```jsonc
"javaHooksEnabled": true,
"javaHooks": [
  {
    "className": "com.example.Logger",
    "methodName": "writeLog",
    "argTypes": ["java.lang.String"],
    "returnType": "void",
    "onCall": { "nop": true }
  },
  {
    "className": "com.example.RootChecker",
    "methodName": "isDeviceRooted",
    "returnType": "boolean",
    "onCall": { "nop": true, "forceReturn": false }
  },
  {
    "className": "com.example.LicenseManager",
    "methodName": "isValidLicense",
    "argTypes": ["java.lang.String", "int"],
    "returnType": "boolean",
    "onCall": { "modifyArgs": { "1": 9999 }, "forceReturn": true }
  }
]
```

### Multi-overload methods

When a method has more than one overload, `argTypes` selects a specific
overload to hook. `argTypes` uses Java source form for primitives
(`"boolean"`, `"int"`, `"long"`) and JNI form for arrays
(`"[B"`, `"[Ljava.lang.String;"`).

```jsonc
"javaHooksEnabled": true,
"javaHooks": [
  // Targets the (String, int) overload only.
  {
    "className": "com.example.Service",
    "methodName": "process",
    "argTypes": ["java.lang.String", "int"],
    "returnType": "void",
    "onCall": { "logArgs": true, "nop": true }
  }
]
```

**Omitting `argTypes` against a multi-overload method** is valid Frida
behavior — assigning `.implementation` to the unresolved method group
hooks every overload with the same implementation. The engine logs a
warning in this case, because the single declared `returnType` gets
used to coerce `forceReturn` and `modifyArgs` for every overload —
which silently produces wrong values for any overload whose real
return type differs from the declared one. Supply `argTypes` unless
you explicitly want to hook every overload with identical behavior.

JNI primitive forms (`"Z"`, `"I"`) are not accepted in `argTypes` — use
the word forms.

### Primitive return types

`returnType` is used only to coerce `forceReturn` and to detect void.
It does not participate in overload resolution.

Accepted word forms: `"void"`, `"boolean"`, `"byte"`, `"short"`,
`"int"`, `"long"`, `"float"`, `"double"`, `"java.lang.String"`.

JNI primitive forms are also accepted (`"V"`, `"Z"`, `"B"`, `"S"`,
`"I"`, `"J"`, `"F"`, `"D"`).

Arrays and object types use JNI form (`"[B"`, `"[Ljava.lang.String;"`,
`"com.example.Model"`).

### Coercion rules for `forceReturn` and `modifyArgs`

| `returnType` / `argTypes[idx]` | Coercion |
|---|---|
| `"boolean"` / `"Z"` | JS value coerced to boolean |
| `"byte"`, `"short"`, `"int"` / `"B"`, `"S"`, `"I"` | JS value coerced to integer |
| `"long"` / `"J"` | JS number, or string parsed via `Long.parseLong()` for values beyond 2^53 |
| `"float"`, `"double"` / `"F"`, `"D"` | JS number, or `parseFloat()` on a string |
| `"char"` / `"C"` | 1-character string; anything else logs a warning and coerces to `"\u0000"` |
| `"java.lang.String"` | `null` passes through; otherwise `String(value)` |
| `"java.lang.Boolean"`, `"Byte"`, `"Short"`, `"Integer"`, `"Long"`, `"Float"`, `"Double"`, `"Character"` | Boxed explicitly via the wrapper class's `valueOf()`. `Long` parses strings via `Long.parseLong()`; `Float` and `Double` parse strings via `parseFloat()`. `null` passes through as `null` |
| Arrays | Passed through the engine; Frida's own argument/return marshalling converts plain JS arrays to/from Java arrays based on the declared signature |
| Custom object types | Passed through unmodified — not supported via config; see the note below the table |

 **Boxed wrapper types.** A method whose declared parameter or return
type is a wrapper class (`java.lang.Boolean`, `java.lang.Integer`,
etc.) needs an actual boxed object, not a bare JS primitive. Frida's
automatic JS↔Java marshalling only covers primitives; autoboxing is a
javac compile-time feature, not a runtime behavior. This matters
especially for Kotlin, where nullable primitives (`Boolean?`, `Int?`,
`Long?`, `Double?`) compile to exactly these wrapper classes — hooking
a Kotlin-compiled method commonly hits this path. The engine boxes
explicitly for every `java.lang.*` wrapper type listed above.

Forcing a return value of a custom object type — say,
`com.example.Result` — is outside the generic path. Supply the object
from a Java hook body instead, or construct it via `Java.use` in a
forked module.

---

## Native hooks

`nativeHooks` accepts typed entries and raw entries. Typed mode is
selected when both `argTypes` and `returnType` are present.

Field reference:
[Modules → Native (.so) Hooking](modules.md#native-so-hooking).

### Typed mode — observe only

```jsonc
{
  "moduleName": "libc.so",
  "symbolName": "srand",
  "argTypes": [],
  "returnType": "void",
  "onCall": { "logArgs": true }
}
```

The original runs and its return value is passed through. `argTypes` and
`returnType` are required — an empty `argTypes` array is valid for a
no-arg function.

### Typed mode — force return

```jsonc
{
  "moduleName": "libtarget.so",
  "offset": "0x1234",
  "argTypes": ["int"],
  "returnType": "int",
  "onCall": { "logArgs": true, "forceReturn": 1 }
}
```

The original still runs. Only the return value observed by the caller is
overridden.

### Typed mode — nop

Skips the original entirely.

```jsonc
{
  "moduleName": "libtarget.so",
  "offset": "0x5678",
  "argTypes": ["pointer"],
  "returnType": "int",
  "onCall": { "nop": true, "forceReturn": 0 }
}
```

`nop` in typed mode returns `forceReturn` if supplied, otherwise `0`
coerced through the declared return type (`ptr(0)` for pointers,
`int64(0)` for 64-bit integers, `0.0` for floats).

### Typed mode — modify args

```jsonc
{
  "moduleName": "libtarget.so",
  "symbolName": "set_threshold",
  "argTypes": ["int", "double"],
  "returnType": "void",
  "onCall": {
    "logArgs": true,
    "modifyArgs": { "0": 999, "1": 0.5 }
  }
}
```

Argument indices are 0-based, coerced through `argTypes[idx]`.

### Typed mode — 64-bit values

`int64` and `uint64` values beyond JavaScript's safe integer range
(2^53) must be supplied as strings.

```jsonc
{
  "moduleName": "libtarget.so",
  "symbolName": "set_timestamp",
  "argTypes": ["int64"],
  "returnType": "int64",
  "onCall": { "modifyArgs": { "0": "9223372036854775807" } }
}
```

### Native type strings

```
void    bool
int8    uint8    int16    uint16
int32   uint32   int64    uint64
int     uint
char    uchar
float   double
pointer
```

`int`/`uint` map to the native C `int` type, which is 32-bit on every
target this engine supports — 32-bit *and* 64-bit alike (`int` does not
widen on a 64-bit build; that's a different C type, `long`, under the
LP64 data model Android's 64-bit ABI uses). This engine does not expose
`long`/`ulong` as a type string at all — for a genuinely 64-bit native
value (on any target bitness), use `int64`/`uint64` explicitly rather
than reaching for `int`/`uint`. Use the explicit-width forms (`int32`,
`uint32`, `int64`, `uint64`) whenever the real size matters, since `int`
is only ever the 32-bit alias here.

### Raw mode — observe only

Selected when either `argTypes` or `returnType` is absent. Arguments and
return value are pointer-sized.

```jsonc
{
  "moduleName": "libc.so",
  "symbolName": "malloc",
  "onCall": { "logArgs": true, "logReturn": true }
}
```

`onCall.nop` is not supported in raw mode — `Interceptor.attach()` cannot
skip the call it observes. A warning is logged and the flag is ignored.

### Raw mode — `rawArgCount`

Raw mode has no `argTypes` to infer the real arity from, so
`onCall.logArgs` logs a fixed number of pointer-sized slots. Default `4`.

```jsonc
{
  "moduleName": "libc.so",
  "symbolName": "memcpy",
  "rawArgCount": 3,
  "onCall": { "logArgs": true }
}
```

Setting this to the function's real arity avoids logging past the end of
the argument list (harmless but misleading) or stopping short.

### Raw mode — force return

```jsonc
{
  "moduleName": "libc.so",
  "symbolName": "getuid",
  "onCall": { "forceReturn": "0x0" }
}
```

The value is coerced via `ptr()`. A raw-mode forced return is a pointer
value regardless of the function's declared C return type.

### Locators

Three ways to identify the target address. Priority order:

| Locator | ASLR-safe | Use for |
|---|---|---|
| `symbolName` | Yes | Exported symbols |
| `offset` (hex string from module base) | Yes | Non-exported / static functions located via reverse engineering |
| `absoluteAddress` (raw pointer) | No | Testing only — after a fresh process launch the address points at unrelated memory |

Exactly one locator per entry.

The module named by `moduleName` must already be loaded when the hook is
installed. A library loaded later will not be picked up unless the hook
is applied again.

---

## Native patches

`nativePatches` writes raw instruction bytes at a specific address. It
is not a function hook — the target's code bytes are edited in place.

Field reference:
[Modules → Native Instruction Patching](modules.md#native-instruction-patching).

### Common ARM64 idioms

| Purpose | Bytes (array form) | Bytes (string form) |
|---|---|---|
| NOP | `["1F", "20", "03", "D5"]` | `"1F2003D5"` |
| RET | `["C0", "03", "5F", "D6"]` | `"C0035FD6"` |
| `MOV W0, #0 ; RET` | `["00", "00", "80", "D2", "C0", "03", "5F", "D6"]` | `"000080D2C0035FD6"` |
| `MOV W0, #1 ; RET` | `["20", "00", "80", "52", "C0", "03", "5F", "D6"]` | `"20008052C0035FD6"` |

### NOP out a check

```jsonc
{
  "moduleName": "libtarget.so",
  "offset": "0x2A10",
  "patchBytes": ["1F", "20", "03", "D5"]
}
```

### Force a boolean return

`MOV W0, #1 ; RET` returns `1` (true). `MOV W0, #0 ; RET` returns `0`
(false).

```jsonc
{
  "moduleName": "libtarget.so",
  "offset": "0x5678",
  "patchBytes": "20008052C0035FD6"
}
```

### Patching multiple instructions

A single `nativePatches` entry can overwrite any number of instructions,
as long as the byte sequence is contiguous.

```jsonc
{
  "moduleName": "libtarget.so",
  "offset": "0x1000",
  "patchBytes": "1F2003D51F2003D5"
}
```

### Reverting

Original bytes are captured before the patch is applied and restored
verbatim on `dispose()`. No manual revert is needed.

### Caveats

- The engine cannot validate that the bytes are well-formed for the
  target CPU. A malformed patch can corrupt execution in ways ranging
  from a crash to silent incorrect behavior elsewhere in the process.
- A string-form `patchBytes` must be non-empty and even-length. A
  malformed string is rejected before any memory is written — no partial
  patch is ever applied.
- Patches install before `sslPinningBypass` by design. See
  [Architecture → Why SSL runs last](architecture.md#why-ssl-runs-last).

---

## Combining config-driven hooks with modules

`javaHooks`, `nativeHooks`, and `nativePatches` run alongside the
feature modules. They are not mutually exclusive with any module flag.

Common combinations:

**Add app-specific Java hooks alongside framework modules:**

```jsonc
"sslPinningBypassEnabled": true,
"javaHooksEnabled": true,
"javaHooks": [
  {
    "className": "com.example.app.Crypto",
    "methodName": "verifySignature",
    "argTypes": ["[B", "[B"],
    "returnType": "boolean",
    "onCall": { "nop": true, "forceReturn": true }
  }
]
```

**Combine native hooks with the VPN/proxy bypass:**

```jsonc
"vpnProxyBypassEnabled": true,
"nativeHooksEnabled": true,
"nativeHooks": [
  {
    "moduleName": "libtarget.so",
    "symbolName": "is_vpn_active",
    "argTypes": [],
    "returnType": "bool",
    "onCall": { "nop": true, "forceReturn": false }
  }
]
```

**Patch a native function and use `RegisterNatives` logging to find the
address:**

```jsonc
"registerNativesLogEnabled": true,
"nativePatchesEnabled": true,
"nativePatches": [
  {
    "moduleName": "libnative-lib.so",
    "offset": "0x1A4C",
    "patchBytes": "000080D2C0035FD6"
  }
]
```

Run once with `registerNativesLogEnabled` to identify the module and
offset, then remove it and keep only the patch entry.

---

## Runtime control

`rpc.exports.init(stage, parameters)` is the engine's entry point. It is
called automatically only in Gadget Script mode. In every other mode,
the user or controller must call it manually.

| Mode | Who calls `init()` | Typical `stage` |
|---|---|---|
| Gadget Script | Gadget, automatically | `"early"` |
| Gadget Listen | Controller | `"late"` |
| Frida CLI — spawn | User, from the REPL | `"early"` |
| Frida CLI — attach | User, from the REPL | `"late"` |

**Frida CLI.** After `frida -U -f <pkg> -l engine.js` (or `-n <name>`
for attach), call from the REPL:

```javascript
rpc.exports.init("early", { sslPinningBypassEnabled: true });
```

Or without parameters — source-level defaults apply:

```javascript
rpc.exports.init("early");
```

**Gadget Listen.** Same call, `stage` is `"late"` because the app is
already running:

```javascript
rpc.exports.init("late", { sslPinningBypassEnabled: true });
```

**`rpc.exports.dispose()`** reverts every applied hook — same behavior as
a Gadget script-unload event. Call it from the same REPL or controller.

**Re-init is not supported.** To change parameters, call `dispose()`,
detach, reattach, then call `init()` again — or restart the app.

`stage` does not change engine behavior; it only appears in the
`[init] stage=...` log line. Use `"early"` when the app has not yet
reached its entrypoint, `"late"` otherwise.

**REPL tip.** Frida's REPL does not accept top-level `await`. For a
single call, no `await` is needed — the RPC fires and hooks install
asynchronously. To confirm resolution before proceeding, wrap in an
async IIFE:

```javascript
(async () => {
  const r = await rpc.exports.init("late", { sslPinningBypassEnabled: true });
  console.log("init resolved:", r);
})();
```

---

## Forking the engine

To modify the engine itself — add a module, change a resolver, adjust the
install order — see
[Architecture → Adding a module](architecture.md#adding-a-module) for
the conventions. For compiling a modified `engine.js` into a
Gadget-loadable agent, see
[Installation → Compiling Your Own Agent](installation.md#compiling-your-own-agent).

---

## Related pages

- [Modules](modules.md) — per-module description and mini config
- [Architecture](architecture.md) — two-phase installation and module-adding conventions
- [Module Limits](limits.md) — platform and coverage boundaries
- [Configuration](configuration.md) — full parameter reference and config model