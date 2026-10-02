# Secure Vault — Electron + React + Go

Modern, encrypted dosya kasası. Dosya adı dahil her şey şifreli.

## Mimari

```
secure-vault/
  app/         Electron + Vite + React + Tailwind (key tutmaz, sadece görüntüler)
    electron/main.cjs      pencere + Go sidecar + event bridge
    electron/preload.cjs   contextBridge (contextIsolation ON, sandbox ON)
    src/renderer/          Lock ekranı + Vault explorer
  vault-core/  Go: tüm kripto (Argon2id + AES-256-GCM chunked) + watcher
```

Güvenlik: key sadece Go RAM'inde, lock'ta sıfırlanır. Renderer key'i hiç görmez.
10 dk hareketsizlikte otomatik kilit. Detay: `VAULT_FORMAT.md`.

## Geliştirme

```powershell
$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
cd secure-vault\vault-core; go build -o vault-core.exe .
cd ..\app; & "C:\Program Files\nodejs\npm.cmd" install
# terminal 1:
& "C:\Program Files\nodejs\npm.cmd" run dev
# terminal 2:
& "C:\Program Files\nodejs\npx.cmd" electron .
```

## Kurulabilir paket (Windows)

```powershell
cd secure-vault\app
& "C:\Program Files\nodejs\npm.cmd" run dist
# çıktı: dist/Secure Vault-Setup-1.0.0.exe (Go çekirdek dahili)
```
