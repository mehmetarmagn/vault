# Vault Format v2

## Directory layout

```
<vault-dir>/
  vault.meta.json   // plaintext: version=2, kdf params, salt, verifier
  index.enc         // AES-GCM(JSON index), nonce prepended
  blobs/
    <random-id>     // VLT2 chunked AES-GCM (no plaintext names on disk)
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
  AAD(chunk i) = blobId + 0x00 + i u32BE   (reorder-resistant)
```

- v1 blobs (`nonce||ct`, AAD=blobId) stay readable (backward compatible); all new writes are v2.
- `Size` in the index is the **plaintext** size (accepted coarse leak; may be hidden in v3).

## IPC (stdio JSON-Line) — commands

`init, unlock, list, status, exists, import, import-folder, cancel-import, open, reencrypt, close, delete, delete-folder, rename, export, export-folder, change-password, lock, ping`

Go → Electron unsolicited events (`id: 0`): `auto-reencrypted`, `file-closed`, `reencrypted`, `import-progress`.
Electron forwards them to the renderer as `vault:event`.

`import-folder` runs in two phases: first `scan`, then `start {total, bytesTotal}`,
progress while sealing as `progress {done, total, current, bytesDone, bytesTotal}`, finally `done`.
Single-file `import` reports too when the file is over 8MB (`op: "import"`).
`export-folder` and `delete-folder` report the same way (`op: "export"` / `"delete"`).
Requests run concurrently; `cancel-import` stops a running transfer.

## Folders (v2.1)

A folder import seals the tree file by file; `Name` holds the relative path
(`proj/src/main.go`). Folders are not separate records — entries group by prefix.
`export-folder` rebuilds the tree on disk, `delete-folder` removes every match.

## Watcher (automatic reseal)

`open` → temp decrypt (0600) + 2s poll watcher. If the temp changes, automatic
re-encrypt + `auto-reencrypted` event. If the temp is deleted, `file-closed`.
`lock` wipes all temps securely (zero over + remove).
