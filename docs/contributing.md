# Contributing

Issues and pull requests are welcome. This page covers how to report a
problem clearly, the code conventions the engine follows, and the
workflow for adding or changing a module.

For the technical conventions a new module must follow — flag
registration, `apply*()` / `revert*()` pairing, hook-install ordering —
see [Architecture → Adding a module](architecture.md#adding-a-module).

---

## Reporting an issue

Before opening an issue, reproduce it with `debugLog: true` so the log
output captures what the engine is doing.

Capture the log:

```bash
adb logcat -s FridaHookEngine:V > hook.log
```

Include in the issue:

- **Engine version** — from the release ZIP or the commit SHA if working
  from source
- **Frida version** — `frida --version`
- **Target package** — the app's package name, not the display name
- **Target device or emulator** — Android version, API level,
  architecture (`arm64-v8a`, `armeabi-v7a`, `x86`, `x86_64`)
- **Deployment mode** — Gadget Script, Gadget Listen, or Frida CLI
- **Config subset** — the `parameters` object in use, or the source-level
  flags that were edited. Not the entire `config.json` — just the keys
  relevant to the issue
- **Log excerpt** — the window from app launch to the point of failure.
  Attach the full `hook.log` if it is large

A reproduction that includes all of the above makes the issue resolvable
without back-and-forth. A report that only says "SSL bypass does not
work" and includes no log cannot be diagnosed.

### Before opening an issue

Check whether the problem is already documented:

- [Troubleshooting](troubleshooting.md) — common failures and their
  resolutions
- [Module Limits](limits.md) — platform and coverage boundaries. Some
  gaps are documented limits, not bugs
- [Configuration](configuration.md) — the wrong-typed-value fallback
  behavior, if a config value appears to have no effect

Many "it does not work" reports are cases where the target reads a
surface the module does not cover, or where the config value is set
without the companion `*Enabled` flag being `true`. Both are documented.

---

## Code style

The engine follows a small set of conventions. New code should match
them.

**Language.** English only — code, comments, docstrings, log messages.

**Fail-safe by default.** A wrong-typed config value must fall back to
its source default with a warning, never crash the engine. A malformed
array entry must be caught per-entry without affecting other entries.

**Wrap hook installs in `try/catch`.** Every individual hook install
gets its own `try/catch`, so a failure on one overload does not abort
the rest. Every hook body also gets its own `try/catch`, so a failure
inside a hooked call does not propagate into the host app.

**Split pre-original and post-original phases.** In a hook body, wrap
the code that runs before the original call in one `try/catch` and the
code that runs after in another. A failure in the post-original phase
must not retry the original — retrying would double its side effects.
See `applyJavaHook()` for the reference implementation.

**Never swallow the original's exceptions.** An exception thrown by the
original implementation is the app's own behavior and must propagate to
the caller. The engine's `try/catch` blocks guard the engine's own
processing, not the original call.

**Log at the right level.**

| Level | Use for |
|---|---|
| `logD` | Per-call detail — argument values, return values, branch decisions inside a hook body |
| `logI` | Install and revert events — one line per module hook set |
| `logW` | Recoverable issues — a hook that failed to install on an unsupported API level, a wrong-typed config value |
| `logE` | Fatal errors — a module that could not be set up at all |

**Use `safeStringify()` for logging values.** A `toString()`
implementation that throws must not abort the hook.

**Follow the existing module pattern.** When adding a module, mirror the
structure of an existing one — the flag declaration, the value-object
declaration (if any), the `apply*()` function, the `revert*()` function,
the `applied*` tracking array, and the wiring in `init()` and
`dispose()`.

---

## Adding a module

The step-by-step convention is documented in
[Architecture → Adding a module](architecture.md#adding-a-module).
Summary of the workflow:

1. **Register a flag.** Declare a module-level `let` with a JSDoc comment
   describing its purpose and its parameter-key override.
2. **Add the value object**, if the module is configurable beyond a
   boolean. Choose the schema that fits — closed-key flat map, open-key
   flat map, nested map, or string array. See
   [Configuration → Value object schemas](configuration.md#value-object-schemas).
3. **Write the `apply*()` function.** Follow the conventions above.
4. **Track every hook.** Push each resolved overload target into a
   dedicated `applied*` array. Reversion uses
   `target.implementation = null` — never a captured snapshot.
5. **Write the `revert*()` function.** Iterate the tracking array, clear
   each target, and empty the array.
6. **Wire the flag into `init()` and `dispose()`.** Add the `resolve*()`
   call, the `apply*()` call inside the `Java.performNow()` block, and
   the `revert*()` call gated on the same flag.
7. **Document the module.** Add an entry to
   [Modules](modules.md#modules), a pairing entry if applicable, and a
   limits entry if the module has a platform boundary.

**Watch the install order.** `applySslPinningBypass()` runs last because
its native `Interceptor.attach()` trampoline must not be overwritten by
`nativePatches`. A new module that installs a native `Interceptor`
must also install after `nativePatches`. See
[Architecture → Why SSL runs last](architecture.md#why-ssl-runs-last).

---

## Testing

Both forms of the engine must be tested for any change:

**Plain script — Frida CLI.** Load directly to verify source-level
defaults work:

```bash
frida -U -f <target-pkg> -l engine.js
```

**Compiled agent — Gadget.** Compile and load via `config.json` to
verify the config-driven path works:

```bash
frida-compile engine.js -o agent.js -c
cp agent.js libfrida-gadget.script.so
```

Test on the lowest API level the module claims to support, and test on a
device or emulator where the module's target class is actually present.
A hook that logs "failed to install" on the wrong test device is not
necessarily a bug in the module — verify the target class exists before
concluding the hook is broken.

For per-module specifics (default values, schema, hook targets), test
against the actual behavior described in [Modules](modules.md), not
against an assumed behavior.

---

## Pull requests

A pull request should:

- Address a single issue or add a single module
- Include the changes to `engine.js` **and** the corresponding updates
  to any affected doc page under `docs/`
- Include a short description of what changed and why
- Reference the issue being resolved, if any

Changes to `agent.js` (the compiled bundle) should not be part of a pull
request — the bundle is regenerated on release. Submit the `engine.js`
change; the maintainer will rebuild `agent.js`.

---

## Related pages

- [Architecture](architecture.md) — two-phase hook installation and module-adding conventions
- [Configuration](configuration.md) — full parameter reference and config model
- [Modules](modules.md) — per-module description and mini config
- [Troubleshooting](troubleshooting.md) — common errors and how to resolve them