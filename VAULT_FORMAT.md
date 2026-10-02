# Vault Format v2

## Dizin yapısı

```
<vault-dir>/
  vault.meta.json   // plaintext: version=2, kdf params, salt, verifier
  index.enc         // AES-GCM(JSON index), nonce prepended
  blobs/
    <random-id>     // VLT2 chunked AES-GCM (diskte plaintext isim YOK)
```

## vault.meta.json

```json
{
  "version": 2,
  "vaultId": "uuid",
  "kdf": { "alg": "argon2id", "time": 3, "memoryKB": 65536, "threads": 4, "saltB64": "...", "keyLen": 32 },
  "verifier": { "nonceB64": "...", "ctB64": "..." }
}
```

`verifier` = `AES-GCM(key, nonce, "vault-verifier-v1:<vaultId>")`.

## Blob format v2 (chunked, 4MB)

```
"VLT2" || chunkSize u32BE || chunk*:
  chunk = nonce(12) || ctLen u32BE || ct
  AAD(chunk i) = blobId + 0x00 + i u32BE   (sıra değiştirmeye dayanıklı)
```

- v1 blob'lar (`nonce||ct`, AAD=blobId) okunabilir (geriye uyumlu), yeni yazımlar hep v2.
- `Size` alanı index'te **plaintext boyutudur** (kaba bilgi sızıntısı kabulü; v3'te gizlenebilir).

## IPC (stdio JSON-Line) — komutlar

`init, unlock, list, status, import, open, reencrypt, close, delete, rename, export, change-password, lock, ping`

Go → Electron istenmeyen event'ler (`id: 0`): `auto-reencrypted`, `file-closed`, `reencrypted`.
Electron bunları `vault:event` ile renderer'a iletir.

## Watcher (otomatik geri şifreleme)

`open` → temp decrypt (0600) + 2 sn poll watcher. Temp değişirse otomatik re-encrypt +
`auto-reencrypted` eventi. Temp silinirse `file-closed`. `lock` tüm temp'leri güvenli siler
(üzerine sıfır yaz + kaldır).
