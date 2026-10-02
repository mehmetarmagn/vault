# Secure Vault — Electron + React + Go

Modern encrypted file vault. Everything is encrypted, filenames included.

## Architecture

```
secure-vault/
  app/         Electron + Vite + React + Tailwind (holds no keys, renders only)
    electron/main.cjs      window + Go sidecar + event bridge
    electron/preload.cjs   contextBridge (contextIsolation ON, sandbox ON)
    src/renderer/          lock screen + vault explorer
  vault-core/  Go: all crypto (Argon2id + AES-256-GCM chunked) + watcher
```

Security: the key lives only in Go RAM, wiped on lock. The renderer never sees it.
Auto-locks after 10 idle minutes. Details: `VAULT_FORMAT.md`.

## Development

```powershell
$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
cd vault\vault-core; go build -o vault-core.exe .
cd ..\app; & "C:\Program Files\nodejs\npm.cmd" install
# terminal 1:
& "C:\Program Files\nodejs\npm.cmd" run dev
# terminal 2:
& "C:\Program Files\nodejs\npx.cmd" electron .
```

## Portable build (Windows)

```powershell
cd vault\app
& "C:\Program Files\nodejs\npm.cmd" run dist:portable
# output: release/Secure Vault-1.0.0-portable.exe (Go core bundled, no installer)
```
