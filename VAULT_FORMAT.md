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

`init, unlock, list, status, exists, import, scan-folder, import-folder, cancel-import, open, read, stream, stream-close, reencrypt, close, delete, delete-folder, rename, export, export-folder, change-password, lan-start, lan-stop, lan-status, lock, ping`

Go → Electron unsolicited events (`id: 0`): `auto-reencrypted`, `file-closed`, `reencrypted`, `import-progress`, `lan-started`, `lan-stopped`, `lan-login`.
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
The scan follows file symlinks and dir junctions (loop-guarded); unreadable or
special files land in `skipped` with reasons, empty dirs in `emptyDirs`.
There is no file-count limit. The UI runs `scan-folder` first and asks
"Encrypt N files?" when the tree holds over 2000 files or 2GB; confirming runs
`import-folder`, which re-scans and seals. Cancelling during scan commits nothing.
Single `delete` commits the index first, then wipes the blocks unlocked, so
`list`/`status` never stall; deleting twice is safe (`already gone`).

## Watcher (automatic reseal)

`open` → temp decrypt (0600) + 2s poll watcher. If the temp changes, automatic
re-encrypt + `auto-reencrypted` event. If the temp is deleted, `file-closed`.
`lock` wipes all temps securely (zero over + remove).

## In-app preview (v2.2)

`read` → decrypted bytes as base64 (cap 100MB, for text/sheets).
`stream` → RAM-only localhost URL (`127.0.0.1`, random port) with `Range`
support for video/audio/PDF/image; `stream-close` drops it. Tokens and buffers
are wiped on `lock`. Nothing previewable ever touches the disk.

## LAN access (v2.2, port 6767)

`lan-start {port, vaultDir}` serves a mobile page + JSON API on `0.0.0.0:port`
(default 6767). Login uses the vault password (same verifier as `unlock`);
5 wrong tries = 60s block. Tokens live 24h and die on `lock`/`lan-stop`.
Endpoints: `GET /` (mobile page), `POST /api/login`, `GET /api/files`,
`GET /api/file?id=`, `GET /api/stream?id=` (Range). Plain HTTP — trusted
local networks only.
