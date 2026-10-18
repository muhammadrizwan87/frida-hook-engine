# Documentation

Reference documentation for Frida Hook Engine. The
[main README](../README.md) covers installation and quick start — start
there first. This folder is for looking things up.

---

## Where to start

Reading order depends on what you are doing.

| Goal | Start with |
|---|---|
| Setting up for the first time | [Installation](installation.md) → [Configuration](configuration.md) |
| Enabling a module on an existing install | [Main README → Modules](../README.md#modules), then [Modules](modules.md) for per-module detail |
| Writing custom hooks | [Advanced Usage](advanced-usage.md) |
| Debugging a hook that does not work | [Troubleshooting](troubleshooting.md), then [Module Limits](limits.md) |
| Understanding module dependencies | [Module Pairing](pairing.md) |
| Forking the engine | [Architecture](architecture.md) |
| Reporting a bug or adding a module | [Contributing](contributing.md) |

---

## Pages

| Page | Covers |
|---|---|
| [Installation](installation.md) | Setup for container, repack, and CLI modes |
| [Configuration](configuration.md) | Full parameter reference and config model |
| [Modules](modules.md) | Per-module description and mini config |
| [Module Pairing](pairing.md) | How modules interact and contribute values |
| [Module Limits](limits.md) | Open vs. closed value maps and platform boundaries |
| [Advanced Usage](advanced-usage.md) | Custom Java hooks, native hooks, native patches |
| [Architecture](architecture.md) | Two-phase hook installation and ordering rules |
| [Troubleshooting](troubleshooting.md) | Common errors and how to resolve them |
| [Contributing](contributing.md) | Bug reports, code style, and module-adding workflow |

---

## Version compatibility

| Environment | Status |
|---|---|
| Frida 17.x | Tested |
| Frida 16.x | Untested |
| Android ARM64 (`arm64-v8a`) | Full support |
| Android 32-bit (`armeabi-v7a`, `x86`) | All modules except the SSL native layer |
| Android 8 (API 26) or newer | Full support |
| Android 7 (API 24) or older | Partial — some hooks target newer APIs |

---

## Directory

```
docs/
├── README.md              ← this file
├── installation.md
├── configuration.md
├── modules.md
├── pairing.md
├── limits.md
├── advanced-usage.md
├── architecture.md
├── troubleshooting.md
└── contributing.md
```

---

## Companion projects

- [keysigner](https://github.com/muhammadrizwan87/keysigner) — APK signing tool
- [frida-bridge](https://github.com/muhammadrizwan87/frida-bridge) — native loader for container / virtual-space environments