# Installation

One-time setup for each deployment mode. Choose the path matching your
access level — Path A and Path B require no root; Path C requires a
rooted device or emulator with `frida-server`.

| Path | Root | Target app repack | Use case |
|---|---|---|---|
| **A — Container / virtual space** | No | No | Embedded gadget, non-root |
| **B — Repack the APK** | No | Yes (one-time) | Embedded gadget, non-root |
| **C — Frida CLI** | Yes | No | Live debugging, attach / spawn |

---

## Path A — Container / Virtual Space

Non-root, no target app repack. Uses [`frida-bridge`](https://github.com/muhammadrizwan87/frida-bridge).

**Prerequisites:**

- A container / virtual-space host on your device
- `frida-bridge` implementation inside the container

**Steps:**

1. Clone the target app inside the container. The container handles this —
   the app appears without modifying the original APK.
2. Create `frida/` inside the target app's private files directory.
   ```
   /data/data/<target.pkg>/files/frida/
   ```
3. Place three files inside `frida/`:
   - `libfrida-gadget.so` — from the engine release ZIP or from
     [Frida latest releases](https://github.com/frida/frida/releases) for your ABI
   - `libfrida-gadget.config.so` — from the engine release ZIP
     (comments stripped for strict JSON parsing)
   - `libfrida-gadget.script.so` — from the engine release ZIP
4. (Optional) Delay gadget load. Create `frida-bridge.cfg` in the same
   folder:
   ```
   delay=3
   ```
   Value in seconds. Default `0`.
5. Run the target app inside the container.

**Verify:**

```bash
adb logcat -s FridaHookEngine:V
```

---

## Path B — Repack the APK

Non-root, one-time rebuild.

**Prerequisites:**

- Decompile tool — Apktool or MT Manager
- A signing tool (any). [`KeySigner`](https://github.com/muhammadrizwan87/keysigner) is one option.

**Steps:**

1. Decompile the APK.
   ```
   apktool d target.apk -o target-src
   ```
   Or use MT Manager's built-in decompiler.

2. Copy the three engine files into the native library directory.
   ```
   target-src/lib/arm64-v8a/
   ├── libfrida-gadget.so          ← from the engine release ZIP or Frida releases
   ├── libfrida-gadget.config.so   ← from the engine release ZIP
   └── libfrida-gadget.script.so   ← from the engine release ZIP
   ```

   32-bit target? Use `lib/armeabi-v7a/`. The SSL native layer requires
   ARM64; the other 20 modules work on any ABI.

3. Add the gadget load call to the app's main `Application` class, inside
   `onCreate()`.

   Java:
   ```java
   @Override
   public void onCreate() {
       super.onCreate();
       System.loadLibrary("frida-gadget");
       // ... rest of onCreate ...
   }
   ```

   Smali:
   ```smali
   # virtual methods
   .method public final onCreate()V
       .registers 2

       const-string v0, "frida-gadget"

       invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V

       invoke-super {p0}, Landroid/app/Application;->onCreate()V

       return-void
   .end method
   ```

   `Application.onCreate()` is required. The engine's framework hooks call
   `Java.use(...)`, which resolves against the app classloader. That
   classloader becomes available after `Application.attachBaseContext()`.
   Loading the gadget earlier triggers a classloader race — see
   [Troubleshooting](troubleshooting.md).

4. Rebuild and sign.
   ```
   apktool b target-src -o rebuilt.apk
   keysigner rebuilt.apk
   ```

5. Install and run.
   ```
   adb install rebuilt.apk
   adb logcat -s FridaHookEngine:V
   ```

---

## Path C — Direct Load via CLI

Rooted device or emulator with `frida-server`.

```bash
git clone https://github.com/muhammadrizwan87/frida-hook-engine
cd frida-hook-engine

# Spawn fresh
frida -U -f com.example.app -l engine.js

# Or attach to a running app
frida -R -n Gadget -l engine.js
```

Non-root devices reach this via a Gadget instance running inside a
container or repacked APK, configured for Listen mode instead of Script
mode. The `-R` flag connects over the network to that instance.

To change which modules run, edit the flags at the top of `engine.js`
(`let sslPinningBypassEnabled = false;` → `true`).

After the script loads, call `rpc.exports.init()` from the REPL to
install hooks — see
[Advanced Usage → Runtime control](advanced-usage.md#runtime-control).

---

## Compiling Your Own Agent

Only needed if you forked `engine.js` or want your own build. End users
of the release ZIP never perform this step — they use the pre-built
`agent.js` with Gadget's Script interaction mode.

**Do not convert `engine.js` to `.ts`.** `frida-compile` accepts plain
JavaScript and TypeScript. Converting to `.ts` introduces type errors,
`@types/frida-gadget` issues, and unnecessary tooling.

### Automated option — online compiler

A community tool handles project creation, dependency management, and
compilation:

> **frida-agent-api** — lightweight Frida agent compiler & API
>
> - GitHub: https://github.com/AbhiTheModder/frida-agent-api
> - Web: https://sheer-darcie-revengisquad-737d9a93.koyeb.app/
>
> Made by Abhi.

### Manual workflow — Termux

**Requirements:**

- Recent Termux from an official source
- Internet access for installing packages
- Python and pip
- Node.js and npm
- Frida CLI tools
- `frida-java-bridge` — Frida 17+ no longer bundles it into the GumJS
  runtime for manually compiled agents
- A plain JavaScript Frida script

**Step 1 — Update Termux**

```bash
pkg update
pkg upgrade
```

**Step 2 — Install packages**

```bash
pkg install python python-pip nodejs npm
```

Verify:

```bash
python --version
pip --version
node --version
npm --version
```

**Step 3 — Install Frida**

```bash
curl -L#o frida-python https://maglit.me/frida-python && bash frida-python
```

Verify:

```bash
frida --version
frida-create --version
frida-compile --version
```

**Step 4 — Create a project directory**

```bash
mkdir -p ~/frida-agent
cd ~/frida-agent
```

**Step 5 — Create the Frida project**

```bash
frida-create -t agent -o .
```

**Step 6 — Install dependencies**

```bash
npm install
npm install frida-java-bridge
```

Frida 17+ no longer bundles the Java/ObjC/Swift bridges into the GumJS
runtime for manually compiled agents. A manually bundled Java agent must
explicitly include `frida-java-bridge`.

**Step 7 — Rename the entry file from `.ts` to `.js`**

The official template is TypeScript-oriented. This workflow uses plain
JavaScript.

```bash
mv agent/index.ts agent/index.js
```

**Step 8 — Put your JavaScript into `agent/index.js`**

```bash
nano agent/index.js
```

**Step 9 — Add the Java import (only if using the Java bridge)**

```javascript
import Java from "frida-java-bridge";

Java.perform(() => {
    console.log("Java bridge loaded");
});
```

Skip this step if the script does not use the Java bridge.

**Step 10 — Keep the file as plain JavaScript**

Specifically, do not:

- Add TypeScript type annotations
- Change JavaScript syntax to TypeScript
- Add interface or type declarations
- Fix Frida TypeScript typings
- Rewrite the script as `.ts`

Keep `agent/index.js` as plain JavaScript. `frida-compile` supports both
TypeScript and JavaScript modules.

**Step 11 — Bundle the JavaScript into one agent file**

```bash
frida-compile agent/index.js -o agent.js -T none -S -c
```

| Flag / argument | Meaning |
|---|---|
| `agent/index.js` | Plain JavaScript source |
| `-o agent.js` | Output bundled agent |
| `-T none` | Disable compiler type-checking |
| `-S` | Omit source maps |
| `-c` | Compress / minify the output |

After a successful build, `agent.js` is created in the project directory.
Rename it for Gadget:

```bash
cp agent.js libfrida-gadget.script.so
```

**Which file to ship:**

| Target | Ship this |
|---|---|
| Non-technical users (Gadget Script mode) | `agent.js` → `libfrida-gadget.script.so` |
| Attaching via Frida CLI | `engine.js` (plain source) |

---

## Related pages

- [Configuration](configuration.md) — full parameter reference and config model
- [Troubleshooting](troubleshooting.md) — common errors and how to resolve them
- [Architecture](architecture.md) — two-phase hook installation and ordering rules