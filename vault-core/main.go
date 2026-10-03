// vault-core v2: chunked AES-256-GCM + CRUD + automatic reseal (watcher).
// IPC: stdin/stdout JSON-Line. Key lives only in this process's RAM.
package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/argon2"
)

const (
	ChunkSize   = 4 * 1024 * 1024 // 4MB
	MaxFileSize = 500 * 1024 * 1024
)

var (
	magicV2 = []byte{'V', 'L', 'T', '2'}
)

// ---------- IPC ----------

type Request struct {
	ID          int    `json:"id"`
	Cmd         string `json:"cmd"`
	VaultDir    string `json:"vaultDir,omitempty"`
	Password    string `json:"password,omitempty"`
	NewPassword string `json:"newPassword,omitempty"`
	Path        string `json:"path,omitempty"`
	DestPath    string `json:"destPath,omitempty"`
	Name        string `json:"name,omitempty"`
	FileID      string `json:"fileId,omitempty"`
	Prefix      string `json:"prefix,omitempty"`
	Token       string `json:"token,omitempty"`
	Port        int    `json:"port,omitempty"`
}

type Response struct {
	ID    int    `json:"id"`
	OK    bool   `json:"ok"`
	Data  any    `json:"data,omitempty"`
	Error string `json:"error,omitempty"`
}

// ---------- Vault ----------

type KDFParams struct {
	Alg      string `json:"alg"`
	Time     uint32 `json:"time"`
	MemoryKB uint32 `json:"memoryKB"`
	Threads  uint8  `json:"threads"`
	SaltB64  string `json:"saltB64"`
	KeyLen   uint32 `json:"keyLen"`
}

type Verifier struct {
	NonceB64 string `json:"nonceB64"`
	CtB64    string `json:"ctB64"`
}

type Meta struct {
	Version int       `json:"version"`
	VaultID string    `json:"vaultId"`
	KDF     KDFParams `json:"kdf"`
	Verify  Verifier  `json:"verifier"`
}

type FileEntry struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Size         int64  `json:"size"` // plaintext boyutu
	Mime         string `json:"mime"`
	Mtime        string `json:"mtime"`
	Format       int    `json:"format"` // 1 legacy, 2 chunked
	BlobNonceB64 string `json:"blobNonceB64,omitempty"`
}

type Index struct {
	Files []FileEntry `json:"files"`
}

type openInfo struct {
	tempPath string
	lastHash [32]byte
	stopCh   chan struct{}
}

type session struct {
	sync.Mutex
	vaultDir string
	key      []byte
	index    Index
	unlocked bool
	open     map[string]*openInfo
}

var sess = session{open: map[string]*openInfo{}}

// folder-import cancel flag (set by cancel-import)
var importCancel atomic.Bool

var stdoutMu sync.Mutex

func emit(v any) {
	stdoutMu.Lock()
	defer stdoutMu.Unlock()
	enc := json.NewEncoder(os.Stdout)
	_ = enc.Encode(v)
}

func fail(id int, msg string)  { emit(Response{ID: id, OK: false, Error: msg}) }
func succeed(id int, data any) { emit(Response{ID: id, OK: true, Data: data}) }
func sendEvent(name string, payload map[string]any) {
	payload["event"] = name
	emit(Response{ID: 0, OK: true, Data: payload})
}

// ---------- helpers ----------

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func randBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return b, err
}

func deriveKey(password string, kdf KDFParams) ([]byte, error) {
	salt, err := base64.StdEncoding.DecodeString(kdf.SaltB64)
	if err != nil {
		return nil, err
	}
	pw := []byte(password)
	key := argon2.IDKey(pw, salt, kdf.Time, kdf.MemoryKB, kdf.Threads, kdf.KeyLen)
	zeroBytes(pw)
	return key, nil
}

func aeadFor(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func defaultKDF() (KDFParams, error) {
	salt, err := randBytes(16)
	if err != nil {
		return KDFParams{}, err
	}
	return KDFParams{
		Alg: "argon2id", Time: 3, MemoryKB: 65536, Threads: 4,
		SaltB64: base64.StdEncoding.EncodeToString(salt), KeyLen: 32,
	}, nil
}

func newID() string {
	b, _ := randBytes(16)
	return fmt.Sprintf("%x", b)
}

func newVaultID() string {
	b, _ := randBytes(16)
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func metaPath(dir string) string  { return filepath.Join(dir, "vault.meta.json") }
func indexPath(dir string) string { return filepath.Join(dir, "index.enc") }
func blobPath(dir, id string) string {
	return filepath.Join(dir, "blobs", id)
}

func verifierString(vaultID string) string { return "vault-verifier-v1:" + vaultID }

func aadForChunk(blobID string, idx uint32) []byte {
	var buf bytes.Buffer
	buf.WriteString(blobID)
	buf.WriteByte(0)
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], idx)
	buf.Write(b[:])
	return buf.Bytes()
}

// encryptFileChunked: VLT2 header + chunks. Each chunk: nonce(12) + ctLen(4BE) + ct.
func encryptFileChunked(key, plaintext []byte, blobID string) ([]byte, error) {
	return encryptFileChunkedProg(key, plaintext, blobID, nil)
}

func encryptFileChunkedProg(key, plaintext []byte, blobID string, prog func(done, total int)) ([]byte, error) {
	aead, err := aeadFor(key)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	out.Write(magicV2)
	var hb [4]byte
	binary.BigEndian.PutUint32(hb[:], uint32(ChunkSize))
	out.Write(hb[:])
	n := (len(plaintext) + ChunkSize - 1) / ChunkSize
	if len(plaintext) == 0 {
		n = 1
	}
	for i := 0; i < n; i++ {
		start := i * ChunkSize
		end := start + ChunkSize
		if end > len(plaintext) {
			end = len(plaintext)
		}
		var chunk []byte
		if len(plaintext) == 0 {
			chunk = []byte{}
		} else {
			chunk = plaintext[start:end]
		}
		nonce, err := randBytes(aead.NonceSize())
		if err != nil {
			return nil, err
		}
		ct := aead.Seal(nil, nonce, chunk, aadForChunk(blobID, uint32(i)))
		out.Write(nonce)
		var lb [4]byte
		binary.BigEndian.PutUint32(lb[:], uint32(len(ct)))
		out.Write(lb[:])
		out.Write(ct)
		if prog != nil {
			prog(i+1, n)
		}
		if len(plaintext) == 0 {
			break
		}
	}
	return out.Bytes(), nil
}

func decryptBlobToPlain(key, raw []byte, blobID string) ([]byte, error) {
	if len(raw) >= 4 && bytes.Equal(raw[:4], magicV2) {
		return decryptChunked(key, raw, blobID)
	}
	// legacy v1: nonce||ct, aad=blobID
	aead, err := aeadFor(key)
	if err != nil {
		return nil, err
	}
	ns := aead.NonceSize()
	if len(raw) < ns {
		return nil, fmt.Errorf("corrupt blob")
	}
	return aead.Open(nil, raw[:ns], raw[ns:], []byte(blobID))
}

func decryptChunked(key, raw []byte, blobID string) ([]byte, error) {
	aead, err := aeadFor(key)
	if err != nil {
		return nil, err
	}
	if len(raw) < 8 {
		return nil, fmt.Errorf("corrupt v2 header")
	}
	off := 8 // magic + chunkSize (chunkSize'ı doğrulamaya gerek yok)
	var out bytes.Buffer
	idx := uint32(0)
	for off < len(raw) {
		if off+12+4 > len(raw) {
			return nil, fmt.Errorf("corrupt chunk header")
		}
		nonce := raw[off : off+12]
		off += 12
		ctLen := binary.BigEndian.Uint32(raw[off : off+4])
		off += 4
		if off+int(ctLen) > len(raw) {
			return nil, fmt.Errorf("corrupt chunk body")
		}
		ct := raw[off : off+int(ctLen)]
		off += int(ctLen)
		pt, err := aead.Open(nil, nonce, ct, aadForChunk(blobID, idx))
		if err != nil {
			return nil, fmt.Errorf("chunk %d decryption failed", idx)
		}
		out.Write(pt)
		zeroBytes(pt)
		idx++
	}
	return out.Bytes(), nil
}

func writeIndexLocked() error {
	plain, err := json.Marshal(sess.index)
	if err != nil {
		return err
	}
	defer zeroBytes(plain)
	aead, err := aeadFor(sess.key)
	if err != nil {
		return err
	}
	nonce, err := randBytes(aead.NonceSize())
	if err != nil {
		return err
	}
	ct := aead.Seal(nil, nonce, plain, nil)
	out := append(nonce, ct...)
	return os.WriteFile(indexPath(sess.vaultDir), out, 0600)
}

func readIndexLocked() error {
	raw, err := os.ReadFile(indexPath(sess.vaultDir))
	if err != nil {
		return err
	}
	aead, err := aeadFor(sess.key)
	if err != nil {
		return err
	}
	ns := aead.NonceSize()
	if len(raw) < ns {
		return fmt.Errorf("corrupt index")
	}
	plain, err := aead.Open(nil, raw[:ns], raw[ns:], nil)
	if err != nil {
		return err
	}
	defer zeroBytes(plain)
	return json.Unmarshal(plain, &sess.index)
}

// zero over in small pieces (no RAM blowup on big files) + fsync
func wipeFileContents(path string) {
	f, err := os.OpenFile(path, os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.Size() <= 0 {
		return
	}
	chunk := make([]byte, 1024*1024)
	var off int64
	remaining := st.Size()
	for remaining > 0 {
		n := int64(len(chunk))
		if n > remaining {
			n = remaining
		}
		if _, err := f.WriteAt(chunk[:n], off); err != nil {
			break
		}
		off += n
		remaining -= n
	}
	_ = f.Sync()
}

func secureWipe(path string) {
	wipeFileContents(path)
	_ = os.Remove(path)
}

func guessMime(name string) string {
	ext := filepath.Ext(name)
	switch ext {
	case ".png":
		return "image/png"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".gif":
		return "image/gif"
	case ".webp":
		return "image/webp"
	case ".svg":
		return "image/svg+xml"
	case ".bmp":
		return "image/bmp"
	case ".pdf":
		return "application/pdf"
	case ".txt", ".md", ".go", ".js", ".ts", ".tsx", ".json", ".html", ".css", ".rs", ".py", ".yml", ".yaml", ".toml", ".log", ".xml", ".csv":
		return "text/plain"
	case ".mp4":
		return "video/mp4"
	case ".webm":
		return "video/webm"
	case ".mkv":
		return "video/x-matroska"
	case ".mov":
		return "video/quicktime"
	case ".avi":
		return "video/x-msvideo"
	case ".mp3":
		return "audio/mpeg"
	case ".wav":
		return "audio/wav"
	case ".ogg", ".oga":
		return "audio/ogg"
	case ".ogv":
		return "video/ogg"
	case ".flac":
		return "audio/flac"
	case ".m4a":
		return "audio/mp4"
	case ".zip":
		return "application/zip"
	case ".xlsx":
		return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
	case ".xls":
		return "application/vnd.ms-excel"
	case ".docx":
		return "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
	default:
		return "application/octet-stream"
	}
}

// ---------- watcher: reseal automatically when the temp file changes ----------

func startWatcher(fileID string) {
	sess.Lock()
	info, ok := sess.open[fileID]
	sess.Unlock()
	if !ok {
		return
	}
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-info.stopCh:
				return
			case <-ticker.C:
				sess.Lock()
				if !sess.unlocked {
					sess.Unlock()
					return
				}
				oi, ok := sess.open[fileID]
				if !ok {
					sess.Unlock()
					return
				}
				tmp := oi.tempPath
				sess.Unlock()

				data, err := os.ReadFile(tmp)
				if err != nil {
					// temp deleted = user closed it, stop the watcher (blob stays sealed)
					sess.Lock()
					if o, ok := sess.open[fileID]; ok && o.tempPath == tmp {
						close(o.stopCh)
						delete(sess.open, fileID)
					}
					sess.Unlock()
					sendEvent("file-closed", map[string]any{"fileId": fileID})
					return
				}
				h := sha256.Sum256(data)
				if h == oi.lastHash {
					continue
				}
				// changed → reseal automatically
				sess.Lock()
				plainLen := int64(len(data))
				enc, err := encryptFileChunked(sess.key, data, fileID)
				zeroBytes(data)
				if err != nil {
					sess.Unlock()
					continue
				}
				_ = os.WriteFile(blobPath(sess.vaultDir, fileID), enc, 0600)
				nowISO := time.Now().UTC().Format(time.RFC3339)
				for i := range sess.index.Files {
					if sess.index.Files[i].ID == fileID {
						sess.index.Files[i].Size = plainLen
						sess.index.Files[i].Mtime = nowISO
					}
				}
				_ = writeIndexLocked()
				// refresh the stored hash
				if cur, err := os.ReadFile(tmp); err == nil {
					oi.lastHash = sha256.Sum256(cur)
				}
				sess.Unlock()
				sendEvent("auto-reencrypted", map[string]any{"fileId": fileID})
			}
		}
	}()
}

func stopWatcher(fileID string) {
	sess.Lock()
	defer sess.Unlock()
	if o, ok := sess.open[fileID]; ok {
		select {
		case <-o.stopCh:
		default:
			close(o.stopCh)
		}
		delete(sess.open, fileID)
	}
}

// ---------- handlers ----------

func handleInit(req Request) {
	sess.Lock()
	defer sess.Unlock()
	if req.VaultDir == "" || req.Password == "" {
		fail(req.ID, "vaultDir and password required")
		return
	}
	if err := os.MkdirAll(filepath.Join(req.VaultDir, "blobs"), 0700); err != nil {
		fail(req.ID, "could not create vault folder: "+err.Error())
		return
	}
	if _, err := os.Stat(metaPath(req.VaultDir)); err == nil {
		fail(req.ID, "vault already exists, use unlock")
		return
	}
	kdf, err := defaultKDF()
	if err != nil {
		fail(req.ID, err.Error())
		return
	}
	key, err := deriveKey(req.Password, kdf)
	if err != nil {
		fail(req.ID, err.Error())
		return
	}
	vaultID := newVaultID()
	aead, _ := aeadFor(key)
	nonce, _ := randBytes(aead.NonceSize())
	ct := aead.Seal(nil, nonce, []byte(verifierString(vaultID)), nil)
	meta := Meta{
		Version: 2, VaultID: vaultID, KDF: kdf,
		Verify: Verifier{
			NonceB64: base64.StdEncoding.EncodeToString(nonce),
			CtB64:    base64.StdEncoding.EncodeToString(ct),
		},
	}
	metaBytes, _ := json.MarshalIndent(meta, "", "  ")
	if err := os.WriteFile(metaPath(req.VaultDir), metaBytes, 0600); err != nil {
		zeroBytes(key)
		fail(req.ID, err.Error())
		return
	}
	sess.vaultDir = req.VaultDir
	sess.key = key
	sess.index = Index{Files: []FileEntry{}}
	sess.unlocked = true
	if err := writeIndexLocked(); err != nil {
		succeed(req.ID, map[string]string{"vaultId": vaultID, "warning": err.Error()})
		return
	}
	succeed(req.ID, map[string]string{"vaultId": vaultID})
}

func handleUnlock(req Request) {
	sess.Lock()
	defer sess.Unlock()
	if req.VaultDir == "" || req.Password == "" {
		fail(req.ID, "vaultDir and password required")
		return
	}
	metaBytes, err := os.ReadFile(metaPath(req.VaultDir))
	if err != nil {
		fail(req.ID, "vault not found, init first")
		return
	}
	var meta Meta
	if err := json.Unmarshal(metaBytes, &meta); err != nil {
		fail(req.ID, "corrupt meta")
		return
	}
	key, err := deriveKey(req.Password, meta.KDF)
	if err != nil {
		fail(req.ID, err.Error())
		return
	}
	nonce, _ := base64.StdEncoding.DecodeString(meta.Verify.NonceB64)
	ct, _ := base64.StdEncoding.DecodeString(meta.Verify.CtB64)
	aead, _ := aeadFor(key)
	plain, err := aead.Open(nil, nonce, ct, nil)
	if err != nil || string(plain) != verifierString(meta.VaultID) {
		zeroBytes(plain)
		zeroBytes(key)
		fail(req.ID, "invalid-password")
		return
	}
	zeroBytes(plain)
	sess.vaultDir = req.VaultDir
	sess.key = key
	sess.unlocked = true
	if err := readIndexLocked(); err != nil {
		zeroBytes(key)
		sess.unlocked = false
		fail(req.ID, "could not decrypt index: "+err.Error())
		return
	}
	succeed(req.ID, map[string]any{"vaultId": meta.VaultID, "files": len(sess.index.Files)})
}

func handleList(req Request) {
	sess.Lock()
	defer sess.Unlock()
	if !sess.unlocked {
		fail(req.ID, "locked")
		return
	}
	succeed(req.ID, sess.index.Files)
}

func handleStatus(req Request) {
	sess.Lock()
	defer sess.Unlock()
	openIDs := []string{}
	for id := range sess.open {
		openIDs = append(openIDs, id)
	}
	succeed(req.ID, map[string]any{"unlocked": sess.unlocked, "files": len(sess.index.Files), "open": openIDs})
}

func handleExists(req Request) {
	if req.VaultDir == "" {
		fail(req.ID, "vaultDir required")
		return
	}
	if _, err := os.Stat(metaPath(req.VaultDir)); err == nil {
		succeed(req.ID, map[string]bool{"exists": true})
		return
	}
	succeed(req.ID, map[string]bool{"exists": false})
}

func handleImport(req Request) {
	sess.Lock()
	defer sess.Unlock()
	if !sess.unlocked {
		fail(req.ID, "locked")
		return
	}
	if req.Path == "" {
		fail(req.ID, "path required")
		return
	}
	st, err := os.Stat(req.Path)
	if err != nil {
		fail(req.ID, err.Error())
		return
	}
	if st.Size() > MaxFileSize {
		fail(req.ID, "file too large (500MB limit)")
		return
	}
	data, err := os.ReadFile(req.Path)
	if err != nil {
		fail(req.ID, err.Error())
		return
	}
	id := newID()
	// report progress per chunk on big files (8MB+)
	big := len(data) > 8*1024*1024
	if big {
		sendEvent("import-progress", map[string]any{
			"op": "import", "phase": "start", "root": filepath.Base(req.Path),
			"total": 1, "bytesTotal": int64(len(data)),
		})
	}
	lastEmit := time.Now()
	enc, err := encryptFileChunkedProg(sess.key, data, id, func(done, total int) {
		if !big || time.Since(lastEmit) < 150*time.Millisecond {
			return
		}
		lastEmit = time.Now()
		frac := float64(done) / float64(total)
		sendEvent("import-progress", map[string]any{
			"op": "import", "phase": "progress", "root": filepath.Base(req.Path),
			"done": done, "total": total, "current": filepath.Base(req.Path),
			"bytesDone": int64(frac * float64(len(data))), "bytesTotal": int64(len(data)),
		})
	})
	plainSize := int64(len(data))
	zeroBytes(data)
	if big {
		sendEvent("import-progress", map[string]any{
			"op": "import", "phase": "done", "root": filepath.Base(req.Path),
			"done": 1, "total": 1,
			"bytesDone": plainSize, "bytesTotal": plainSize,
			"cancelled": false,
		})
	}
	if err != nil {
		fail(req.ID, err.Error())
		return
	}
	if err := os.WriteFile(blobPath(sess.vaultDir, id), enc, 0600); err != nil {
		fail(req.ID, err.Error())
		return
	}
	entry := FileEntry{
		ID: id, Name: filepath.Base(req.Path),
		Size: plainSize, Mime: guessMime(req.Path),
		Mtime:  st.ModTime().UTC().Format(time.RFC3339),
		Format: 2,
	}
	sess.index.Files = append(sess.index.Files, entry)
	if err := writeIndexLocked(); err != nil {
		fail(req.ID, err.Error())
		return
	}
	succeed(req.ID, entry)
}

const MaxPreviewSize = 100 * 1024 * 1024 // in-app read cap (bigger: use stream or external open)

// ---------- in-app preview: RAM-only stream server (no disk) ----------

type streamEntry struct {
	data []byte
	mime string
	name string
}

var (
	streamMu      sync.Mutex
	streams       = map[string]*streamEntry{}
	streamBaseURL = ""
)

func ensureStreamServer() string {
	streamMu.Lock()
	defer streamMu.Unlock()
	if streamBaseURL != "" {
		return streamBaseURL
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/s/", func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.URL.Path, "/s/")
		streamMu.Lock()
		e, ok := streams[token]
		streamMu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		if e.mime != "" {
			w.Header().Set("Content-Type", e.mime)
		}
		w.Header().Set("Accept-Ranges", "bytes")
		w.Header().Set("Cache-Control", "no-store")
		http.ServeContent(w, r, e.name, time.Now(), bytes.NewReader(e.data))
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return ""
	}
	go func() {
		_ = http.Serve(ln, mux)
	}()
	streamBaseURL = "http://" + ln.Addr().String()
	return streamBaseURL
}

func clearStreamsLocked() {
	for token, e := range streams {
		zeroBytes(e.data)
		delete(streams, token)
	}
}

func handleRead(req Request) {
	sess.Lock()
	defer sess.Unlock()
	if !sess.unlocked {
		fail(req.ID, "locked")
		return
	}
	var entry *FileEntry
	for i := range sess.index.Files {
		if sess.index.Files[i].ID == req.FileID {
			entry = &sess.index.Files[i]
			break
		}
	}
	if entry == nil {
		fail(req.ID, "file not found")
		return
	}
	raw, err := os.ReadFile(blobPath(sess.vaultDir, entry.ID))
	if err != nil {
		fail(req.ID, err.Error())
		return
	}
	plain, err := decryptBlobToPlain(sess.key, raw, entry.ID)
	if err != nil {
		fail(req.ID, "decryption failed")
		return
	}
	defer zeroBytes(plain)
	if int64(len(plain)) > MaxPreviewSize {
		fail(req.ID, "too large for in-app preview (use open or stream)")
		return
	}
	succeed(req.ID, map[string]any{
		"name": entry.Name, "mime": entry.Mime, "size": len(plain),
		"b64": base64.StdEncoding.EncodeToString(plain),
	})
}

func handleStream(req Request) {
	sess.Lock()
	var entry *FileEntry
	for i := range sess.index.Files {
		if sess.index.Files[i].ID == req.FileID {
			entry = &sess.index.Files[i]
			break
		}
	}
	if !sess.unlocked || entry == nil {
		sess.Unlock()
		fail(req.ID, "file not found")
		return
	}
	raw, err := os.ReadFile(blobPath(sess.vaultDir, entry.ID))
	if err != nil {
		sess.Unlock()
		fail(req.ID, err.Error())
		return
	}
	plain, err := decryptBlobToPlain(sess.key, raw, entry.ID)
	if err != nil {
		sess.Unlock()
		fail(req.ID, "decryption failed")
		return
	}
	mime, name := entry.Mime, entry.Name
	sess.Unlock()
	base := ensureStreamServer()
	if base == "" {
		zeroBytes(plain)
		fail(req.ID, "stream server failed")
		return
	}
	token := newID()
	streamMu.Lock()
	streams[token] = &streamEntry{data: plain, mime: mime, name: name}
	streamMu.Unlock()
	succeed(req.ID, map[string]any{
		"url": base + "/s/" + token, "token": token, "mime": mime,
		"name": name, "size": len(plain),
	})
}

func handleStreamClose(req Request) {
	streamMu.Lock()
	defer streamMu.Unlock()
	if req.Token != "" {
		if e, ok := streams[req.Token]; ok {
			zeroBytes(e.data)
			delete(streams, req.Token)
		}
	}
	succeed(req.ID, map[string]bool{"closed": true})
}

// folder scan: follows file symlinks and dir junctions, guards link loops,
// reports skipped files AND empty dirs (a vault stores files, not folders).
type importJob struct {
	path  string
	name  string
	mime  string
	mtime string
	size  int64
}

// scan reports are capped so a monster tree can't flood the IPC channel;
// the overflow lands in skippedExtra / emptyExtra.
const maxScanReport = 500

func scanImportTree(root, base string) (jobs []importJob, skipped []map[string]string, skippedExtra int, emptyDirs []string, emptyExtra int) {
	visited := map[string]bool{} // canonical dir -> seen (link loop guard)
	hasFiles := map[string]bool{}
	var allDirs []string
	addSkipped := func(path, reason string) {
		if len(skipped) < maxScanReport {
			skipped = append(skipped, map[string]string{"path": path, "reason": reason})
		} else {
			skippedExtra++
		}
	}
	canon := func(dir string) string {
		if c, err := filepath.EvalSymlinks(dir); err == nil {
			return c
		}
		if abs, err := filepath.Abs(dir); err == nil {
			return abs
		}
		return dir
	}
	markTree := func(logical string) {
		for p := logical; ; {
			hasFiles[p] = true
			i := strings.LastIndex(p, "/")
			if i < 0 {
				break
			}
			p = p[:i]
		}
	}
	var rec func(dir, logical string)
	rec = func(dir, logical string) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			addSkipped(dir, err.Error())
			return
		}
		c := canon(dir)
		if visited[c] {
			addSkipped(dir, "already visited (link loop), skipped")
			return
		}
		visited[c] = true
		allDirs = append(allDirs, logical)
		for _, e := range entries {
			full := filepath.Join(dir, e.Name())
			vname := logical + "/" + e.Name()
			info, err := e.Info()
			if err != nil {
				addSkipped(full, err.Error())
				continue
			}
			if info.IsDir() {
				rec(full, vname)
				continue
			}
			var fi os.FileInfo
			if info.Mode().IsRegular() {
				fi = info
			} else if st, err := os.Stat(full); err != nil {
				// broken link (or unreadable reparse point)
				addSkipped(full, "unreadable link target: "+err.Error())
				continue
			} else if st.IsDir() {
				// junction / dir symlink: descend, logical name preserved
				rec(full, vname)
				continue
			} else if !st.Mode().IsRegular() {
				addSkipped(full, "not a regular file")
				continue
			} else {
				fi = st // file symlink: seal the target's content
			}
			if fi.Size() > MaxFileSize {
				addSkipped(full, "file too large (500MB limit)")
				continue
			}
			jobs = append(jobs, importJob{
				path: full, name: vname, mime: guessMime(full),
				mtime: fi.ModTime().UTC().Format(time.RFC3339), size: fi.Size(),
			})
			markTree(logical)
		}
	}
	rec(root, base)
	for _, d := range allDirs {
		if !hasFiles[d] {
			if len(emptyDirs) < maxScanReport {
				emptyDirs = append(emptyDirs, d)
			} else {
				emptyExtra++
			}
		}
	}
	return jobs, skipped, skippedExtra, emptyDirs, emptyExtra
}

// folder prefix match: "proj" == name or name starts with "proj/..."
func matchPrefix(name, prefix string) bool {
	if prefix == "" {
		return false
	}
	return name == prefix || strings.HasPrefix(name, prefix+"/")
}

func handleScanFolder(req Request) {
	sess.Lock()
	unlocked := sess.unlocked
	sess.Unlock()
	if !unlocked {
		fail(req.ID, "locked")
		return
	}
	if req.Path == "" {
		fail(req.ID, "path required")
		return
	}
	st, err := os.Stat(req.Path)
	if err != nil {
		fail(req.ID, err.Error())
		return
	}
	if !st.IsDir() {
		fail(req.ID, "not a folder, use import for files")
		return
	}
	base := filepath.Base(req.Path)
	jobs, skipped, skippedExtra, emptyDirs, emptyExtra := scanImportTree(req.Path, base)
	var bytesTotal int64
	for _, j := range jobs {
		bytesTotal += j.size
	}
	succeed(req.ID, map[string]any{
		"root": base, "total": len(jobs), "bytesTotal": bytesTotal,
		"skipped": skipped, "skippedExtra": skippedExtra,
		"emptyDirs": emptyDirs, "emptyExtra": emptyExtra,
	})
}

func handleImportFolder(req Request) {
	sess.Lock()
	defer sess.Unlock()
	if !sess.unlocked {
		fail(req.ID, "locked")
		return
	}
	if req.Path == "" {
		fail(req.ID, "path required")
		return
	}
	st, err := os.Stat(req.Path)
	if err != nil {
		fail(req.ID, err.Error())
		return
	}
	if !st.IsDir() {
		fail(req.ID, "not a folder, use import for files")
		return
	}
	root := req.Path
	base := filepath.Base(root)
	importCancel.Store(false)
	sendEvent("import-progress", map[string]any{"op": "import", "phase": "scan", "root": base})

	// phase 1: scan, build the job list (lock released — disk reads only)
	sess.Unlock()
	jobs, skipped, skippedExtra, emptyDirs, emptyExtra := scanImportTree(root, base)
	sess.Lock()
	if !sess.unlocked {
		fail(req.ID, "locked")
		return
	}
	if importCancel.Load() {
		// cancelled during scan: nothing sealed, nothing committed
		// (lock is held here; the deferred Unlock releases it)
		succeed(req.ID, map[string]any{"imported": []FileEntry{}, "skipped": skipped, "skippedExtra": skippedExtra, "emptyDirs": emptyDirs, "emptyExtra": emptyExtra, "cancelled": true})
		return
	}
	var bytesTotal int64
	for _, j := range jobs {
		bytesTotal += j.size
	}
	total := len(jobs)
	if total == 0 {
		reason := "no importable files in folder"
		if len(skipped) > 0 {
			reason = skipped[0]["reason"]
		} else if len(emptyDirs) > 0 {
			reason = fmt.Sprintf("%d empty folder(s) — the vault stores files, not empty folders", len(emptyDirs))
		}
		fail(req.ID, "nothing imported: "+reason)
		return
	}
	sendEvent("import-progress", map[string]any{
		"op": "import", "phase": "start", "root": base, "total": total, "bytesTotal": bytesTotal,
	})

	// phase 2: encrypt + write (progress in a low voice)
	taken := map[string]bool{}
	for _, f := range sess.index.Files {
		taken[f.Name] = true
	}
	unique := func(name string) string {
		if !taken[name] {
			taken[name] = true
			return name
		}
		ext := filepath.Ext(name)
		stem := strings.TrimSuffix(name, ext)
		for i := 2; ; i++ {
			cand := fmt.Sprintf("%s (%d)%s", stem, i, ext)
			if !taken[cand] {
				taken[cand] = true
				return cand
			}
		}
	}
	var imported []FileEntry
	var bytesDone int64
	cancelled := false
	lastEmit := time.Now()
	emitProg := func(force bool, cur string) {
		if !force && time.Since(lastEmit) < 150*time.Millisecond {
			return
		}
		lastEmit = time.Now()
		sendEvent("import-progress", map[string]any{
			"op": "import", "phase": "progress", "root": base,
			"done": len(imported), "total": total,
			"current": cur, "bytesDone": bytesDone, "bytesTotal": bytesTotal,
		})
	}
	for _, j := range jobs {
		if importCancel.Load() {
			cancelled = true
			break
		}
		data, err := os.ReadFile(j.path)
		if err != nil {
			skipped = append(skipped, map[string]string{"path": j.path, "reason": err.Error()})
			continue
		}
		name := unique(j.name)
		id := newID()
		enc, err := encryptFileChunked(sess.key, data, id)
		plainSize := int64(len(data))
		zeroBytes(data)
		if err != nil {
			skipped = append(skipped, map[string]string{"path": j.path, "reason": err.Error()})
			continue
		}
		if err := os.WriteFile(blobPath(sess.vaultDir, id), enc, 0600); err != nil {
			skipped = append(skipped, map[string]string{"path": j.path, "reason": err.Error()})
			continue
		}
		imported = append(imported, FileEntry{
			ID: id, Name: name,
			Size: plainSize, Mime: j.mime,
			Mtime:  j.mtime,
			Format: 2,
		})
		bytesDone += j.size
		emitProg(false, name)
	}
	// commit to the index in one go
	sess.index.Files = append(sess.index.Files, imported...)
	if err := writeIndexLocked(); err != nil {
		fail(req.ID, err.Error())
		return
	}
	emitProg(true, "")
	sendEvent("import-progress", map[string]any{
		"op": "import", "phase": "done", "root": base,
		"done": len(imported), "total": total,
		"bytesDone": bytesDone, "bytesTotal": bytesTotal,
		"cancelled": cancelled,
	})
	succeed(req.ID, map[string]any{"imported": imported, "skipped": skipped, "skippedExtra": skippedExtra, "emptyDirs": emptyDirs, "emptyExtra": emptyExtra, "cancelled": cancelled})
}

func handleCancelImport(req Request) {
	importCancel.Store(true)
	succeed(req.ID, map[string]bool{"cancelling": true})
}

func handleExportFolder(req Request) {
	sess.Lock()
	defer sess.Unlock()
	if !sess.unlocked {
		fail(req.ID, "locked")
		return
	}
	if req.Prefix == "" || req.DestPath == "" {
		fail(req.ID, "prefix and destPath required")
		return
	}
	type target struct {
		id, name, rel string
		size          int64
	}
	var targets []target
	var bytesTotal int64
	for _, f := range sess.index.Files {
		if !matchPrefix(f.Name, req.Prefix) {
			continue
		}
		rel := strings.TrimPrefix(f.Name, req.Prefix)
		rel = strings.TrimPrefix(rel, "/")
		if rel == "" {
			continue
		}
		targets = append(targets, target{id: f.ID, name: f.Name, rel: rel, size: f.Size})
		bytesTotal += f.Size
	}
	if len(targets) == 0 {
		fail(req.ID, "folder not found")
		return
	}
	importCancel.Store(false)
	total := len(targets)
	sendEvent("import-progress", map[string]any{
		"op": "export", "phase": "start", "root": req.Prefix,
		"total": total, "bytesTotal": bytesTotal,
	})
	n := 0
	var bytesDone int64
	cancelled := false
	lastEmit := time.Now()
	for _, t := range targets {
		if importCancel.Load() {
			cancelled = true
			break
		}
		raw, err := os.ReadFile(blobPath(sess.vaultDir, t.id))
		if err != nil {
			fail(req.ID, "could not read blob: "+t.name)
			return
		}
		plain, err := decryptBlobToPlain(sess.key, raw, t.id)
		if err != nil {
			fail(req.ID, "decryption failed: "+t.name)
			return
		}
		out := filepath.Join(req.DestPath, filepath.FromSlash(t.rel))
		if err := os.MkdirAll(filepath.Dir(out), 0700); err != nil {
			zeroBytes(plain)
			fail(req.ID, err.Error())
			return
		}
		if err := os.WriteFile(out, plain, 0600); err != nil {
			zeroBytes(plain)
			fail(req.ID, err.Error())
			return
		}
		zeroBytes(plain)
		n++
		bytesDone += t.size
		if time.Since(lastEmit) > 150*time.Millisecond {
			lastEmit = time.Now()
			sendEvent("import-progress", map[string]any{
				"op": "export", "phase": "progress", "root": req.Prefix,
				"done": n, "total": total, "current": t.name,
				"bytesDone": bytesDone, "bytesTotal": bytesTotal,
			})
		}
	}
	sendEvent("import-progress", map[string]any{
		"op": "export", "phase": "done", "root": req.Prefix,
		"done": n, "total": total,
		"bytesDone": bytesDone, "bytesTotal": bytesTotal,
		"cancelled": cancelled,
	})
	succeed(req.ID, map[string]any{"exported": n, "destPath": req.DestPath, "cancelled": cancelled})
}

func handleDeleteFolder(req Request) {
	sess.Lock()
	defer sess.Unlock()
	if !sess.unlocked {
		fail(req.ID, "locked")
		return
	}
	if req.Prefix == "" {
		fail(req.ID, "prefix required")
		return
	}
	type target struct {
		id, name string
		size     int64
	}
	var targets []target
	var bytesTotal int64
	for _, f := range sess.index.Files {
		if matchPrefix(f.Name, req.Prefix) {
			targets = append(targets, target{id: f.ID, name: f.Name, size: f.Size})
			bytesTotal += f.Size
		}
	}
	if len(targets) == 0 {
		sess.Unlock()
		succeed(req.ID, map[string]any{"deleted": 0, "note": "already gone"})
		return
	}
	importCancel.Store(false)
	total := len(targets)
	sendEvent("import-progress", map[string]any{
		"op": "delete", "phase": "start", "root": req.Prefix,
		"total": total, "bytesTotal": bytesTotal,
	})
	gone := map[string]bool{}
	var bytesDone int64
	cancelled := false
	lastEmit := time.Now()
	for _, t := range targets {
		if importCancel.Load() {
			cancelled = true
			break
		}
		if o, ok := sess.open[t.id]; ok {
			select {
			case <-o.stopCh:
			default:
				close(o.stopCh)
			}
			secureWipe(o.tempPath)
			delete(sess.open, t.id)
		}
		bp := blobPath(sess.vaultDir, t.id)
		wipeFileContents(bp)
		_ = os.Remove(bp)
		gone[t.id] = true
		bytesDone += t.size
		if time.Since(lastEmit) > 150*time.Millisecond {
			lastEmit = time.Now()
			sendEvent("import-progress", map[string]any{
				"op": "delete", "phase": "progress", "root": req.Prefix,
				"done": len(gone), "total": total, "current": t.name,
				"bytesDone": bytesDone, "bytesTotal": bytesTotal,
			})
		}
	}
	kept := sess.index.Files[:0]
	for _, f := range sess.index.Files {
		if !gone[f.ID] {
			kept = append(kept, f)
		}
	}
	sess.index.Files = kept
	_ = writeIndexLocked()
	sendEvent("import-progress", map[string]any{
		"op": "delete", "phase": "done", "root": req.Prefix,
		"done": len(gone), "total": total,
		"bytesDone": bytesDone, "bytesTotal": bytesTotal,
		"cancelled": cancelled,
	})
	succeed(req.ID, map[string]any{"deleted": len(gone), "cancelled": cancelled})
}

func handleOpen(req Request) {
	// fast path: already open, return the existing temp
	sess.Lock()
	if !sess.unlocked {
		sess.Unlock()
		fail(req.ID, "locked")
		return
	}
	if o, ok := sess.open[req.FileID]; ok {
		tmp := o.tempPath
		sess.Unlock()
		succeed(req.ID, map[string]string{"tempPath": tmp, "reused": "true"})
		return
	}
	var entry *FileEntry
	for i := range sess.index.Files {
		if sess.index.Files[i].ID == req.FileID {
			entry = &sess.index.Files[i]
			break
		}
	}
	if entry == nil {
		sess.Unlock()
		fail(req.ID, "file not found")
		return
	}
	raw, err := os.ReadFile(blobPath(sess.vaultDir, entry.ID))
	if err != nil {
		sess.Unlock()
		fail(req.ID, err.Error())
		return
	}
	plain, err := decryptBlobToPlain(sess.key, raw, entry.ID)
	if err != nil {
		sess.Unlock()
		fail(req.ID, "decryption failed")
		return
	}
	tmp, err := os.CreateTemp("", "vault-"+entry.ID+"-*"+filepath.Ext(entry.Name))
	if err != nil {
		zeroBytes(plain)
		sess.Unlock()
		fail(req.ID, err.Error())
		return
	}
	_ = tmp.Chmod(0600)
	if _, err := tmp.Write(plain); err != nil {
		zeroBytes(plain)
		_ = tmp.Close()
		sess.Unlock()
		fail(req.ID, err.Error())
		return
	}
	zeroBytes(plain)
	_ = tmp.Close()
	h := sha256.Sum256(func() []byte { d, _ := os.ReadFile(tmp.Name()); return d }())
	sess.open[entry.ID] = &openInfo{tempPath: tmp.Name(), lastHash: h, stopCh: make(chan struct{})}
	name := entry.Name
	sess.Unlock()
	startWatcher(entry.ID)
	succeed(req.ID, map[string]string{"tempPath": tmp.Name(), "name": name})
}

func handleReencrypt(req Request) {
	fileID := req.FileID
	sess.Lock()
	if !sess.unlocked {
		sess.Unlock()
		fail(req.ID, "locked")
		return
	}
	oi, ok := sess.open[fileID]
	if !ok {
		sess.Unlock()
		fail(req.ID, "no open file (already sealed)")
		return
	}
	tmp := oi.tempPath
	select {
	case <-oi.stopCh:
	default:
		close(oi.stopCh)
	}
	delete(sess.open, fileID)
	data, err := os.ReadFile(tmp)
	if err != nil {
		sess.Unlock()
		fail(req.ID, err.Error())
		return
	}
	plainLen := int64(len(data))
	enc, err := encryptFileChunked(sess.key, data, fileID)
	zeroBytes(data)
	if err != nil {
		sess.Unlock()
		fail(req.ID, err.Error())
		return
	}
	_ = os.WriteFile(blobPath(sess.vaultDir, fileID), enc, 0600)
	nowISO := time.Now().UTC().Format(time.RFC3339)
	for i := range sess.index.Files {
		if sess.index.Files[i].ID == fileID {
			sess.index.Files[i].Size = plainLen
			sess.index.Files[i].Mtime = nowISO
		}
	}
	_ = writeIndexLocked()
	sess.Unlock()
	secureWipe(tmp)
	sendEvent("reencrypted", map[string]any{"fileId": fileID})
	succeed(req.ID, map[string]string{"reencrypted": fileID})
}

func handleClose(req Request) {
	// close without saving: drop the temp, leave the blob as is
	sess.Lock()
	oi, ok := sess.open[req.FileID]
	if !ok {
		sess.Unlock()
		fail(req.ID, "no open file")
		return
	}
	select {
	case <-oi.stopCh:
	default:
		close(oi.stopCh)
	}
	delete(sess.open, req.FileID)
	tmp := oi.tempPath
	sess.Unlock()
	secureWipe(tmp)
	sendEvent("file-closed", map[string]any{"fileId": req.FileID})
	succeed(req.ID, map[string]string{"closed": req.FileID})
}

func handleDelete(req Request) {
	// commit-then-wipe: the index updates under a short lock, the slow
	// overwrite runs unlocked so list/status never freeze behind a delete.
	sess.Lock()
	if !sess.unlocked {
		sess.Unlock()
		fail(req.ID, "locked")
		return
	}
	found := false
	for _, f := range sess.index.Files {
		if f.ID == req.FileID {
			found = true
			break
		}
	}
	var tempPath string
	if o, ok := sess.open[req.FileID]; ok {
		select {
		case <-o.stopCh:
		default:
			close(o.stopCh)
		}
		tempPath = o.tempPath
		delete(sess.open, req.FileID)
	}
	if !found && tempPath == "" {
		sess.Unlock()
		succeed(req.ID, map[string]string{"deleted": req.FileID, "note": "already gone"})
		return
	}
	kept := sess.index.Files[:0]
	for _, f := range sess.index.Files {
		if f.ID != req.FileID {
			kept = append(kept, f)
		}
	}
	sess.index.Files = kept
	werr := writeIndexLocked()
	vaultDir := sess.vaultDir
	sess.Unlock()
	if werr != nil {
		fail(req.ID, werr.Error())
		return
	}
	if tempPath != "" {
		secureWipe(tempPath)
	}
	bp := blobPath(vaultDir, req.FileID)
	wipeFileContents(bp)
	_ = os.Remove(bp)
	succeed(req.ID, map[string]string{"deleted": req.FileID})
}

func handleRename(req Request) {
	sess.Lock()
	defer sess.Unlock()
	if !sess.unlocked {
		fail(req.ID, "locked")
		return
	}
	if req.Name == "" {
		fail(req.ID, "new name required")
		return
	}
	for i := range sess.index.Files {
		if sess.index.Files[i].ID == req.FileID {
			sess.index.Files[i].Name = filepath.Base(req.Name)
			sess.index.Files[i].Mime = guessMime(req.Name)
			_ = writeIndexLocked()
			succeed(req.ID, sess.index.Files[i])
			return
		}
	}
	fail(req.ID, "file not found")
}

func handleExport(req Request) {
	sess.Lock()
	defer sess.Unlock()
	if !sess.unlocked {
		fail(req.ID, "locked")
		return
	}
	if req.DestPath == "" {
		fail(req.ID, "destPath required")
		return
	}
	found := false
	for _, f := range sess.index.Files {
		if f.ID == req.FileID {
			found = true
			break
		}
	}
	if !found {
		fail(req.ID, "file not found")
		return
	}
	raw, err := os.ReadFile(blobPath(sess.vaultDir, req.FileID))
	if err != nil {
		fail(req.ID, err.Error())
		return
	}
	plain, err := decryptBlobToPlain(sess.key, raw, req.FileID)
	if err != nil {
		fail(req.ID, "decryption failed")
		return
	}
	defer zeroBytes(plain)
	if err := os.WriteFile(req.DestPath, plain, 0600); err != nil {
		fail(req.ID, err.Error())
		return
	}
	succeed(req.ID, map[string]string{"exported": req.DestPath})
}

func handleChangePassword(req Request) {
	sess.Lock()
	defer sess.Unlock()
	if !sess.unlocked {
		fail(req.ID, "locked")
		return
	}
	if req.NewPassword == "" || len(req.NewPassword) < 8 {
		fail(req.ID, "new password must be at least 8 characters")
		return
	}
	newKDF, err := defaultKDF()
	if err != nil {
		fail(req.ID, err.Error())
		return
	}
	newKey, err := deriveKey(req.NewPassword, newKDF)
	if err != nil {
		fail(req.ID, err.Error())
		return
	}
	// decrypt every blob with the old key, seal with the new one
	for _, f := range sess.index.Files {
		raw, err := os.ReadFile(blobPath(sess.vaultDir, f.ID))
		if err != nil {
			zeroBytes(newKey)
			fail(req.ID, "could not read blob: "+f.Name)
			return
		}
		plain, err := decryptBlobToPlain(sess.key, raw, f.ID)
		if err != nil {
			zeroBytes(newKey)
			fail(req.ID, "decryption failed: "+f.Name)
			return
		}
		enc, err := encryptFileChunked(newKey, plain, f.ID)
		zeroBytes(plain)
		if err != nil {
			zeroBytes(newKey)
			fail(req.ID, err.Error())
			return
		}
		_ = os.WriteFile(blobPath(sess.vaultDir, f.ID), enc, 0600)
	}
	// update the meta
	metaBytes, _ := os.ReadFile(metaPath(sess.vaultDir))
	var meta Meta
	_ = json.Unmarshal(metaBytes, &meta)
	meta.KDF = newKDF
	aead, _ := aeadFor(newKey)
	nonce, _ := randBytes(aead.NonceSize())
	ct := aead.Seal(nil, nonce, []byte(verifierString(meta.VaultID)), nil)
	meta.Verify = Verifier{
		NonceB64: base64.StdEncoding.EncodeToString(nonce),
		CtB64:    base64.StdEncoding.EncodeToString(ct),
	}
	out, _ := json.MarshalIndent(meta, "", "  ")
	_ = os.WriteFile(metaPath(sess.vaultDir), out, 0600)
	zeroBytes(sess.key)
	sess.key = newKey
	_ = writeIndexLocked()
	succeed(req.ID, map[string]bool{"changed": true})
}

func handleLock(req Request) {
	sess.Lock()
	openTemps := []string{}
	for id, o := range sess.open {
		select {
		case <-o.stopCh:
		default:
			close(o.stopCh)
		}
		openTemps = append(openTemps, o.tempPath)
		delete(sess.open, id)
	}
	if sess.key != nil {
		zeroBytes(sess.key)
		sess.key = nil
	}
	sess.index = Index{}
	sess.unlocked = false
	sess.vaultDir = ""
	sess.Unlock()
	clearStreamsLocked()
	clearLanTokens()
	for _, t := range openTemps {
		secureWipe(t)
	}
	succeed(req.ID, map[string]bool{"locked": true})
}

// ---------- LAN access: phone on the same Wi-Fi, port 6767 ----------
// Serves a small mobile page + JSON API on 0.0.0.0. Login uses the vault
// password (same verifier as unlock). Tokens live 24h, 5 wrong tries = 60s block.

type lanState struct {
	sync.Mutex
	running    bool
	port       int
	vaultDir   string
	srv        *http.Server
	ln         net.Listener
	tokens     map[string]time.Time
	failCount  int
	blockUntil time.Time
}

var lan = lanState{tokens: map[string]time.Time{}}

const lanTokenTTL = 24 * time.Hour

func clearLanTokens() {
	lan.Lock()
	defer lan.Unlock()
	for t := range lan.tokens {
		delete(lan.tokens, t)
	}
	lan.failCount = 0
	lan.blockUntil = time.Time{}
}

func lanCheckToken(r *http.Request) bool {
	tok := r.URL.Query().Get("token")
	if tok == "" {
		if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
			tok = strings.TrimPrefix(h, "Bearer ")
		}
	}
	if tok == "" {
		return false
	}
	lan.Lock()
	defer lan.Unlock()
	exp, ok := lan.tokens[tok]
	if !ok || time.Now().After(exp) {
		delete(lan.tokens, tok)
		return false
	}
	return true
}

func lanWriteJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// verify password against a vault dir without touching the live session
func lanVerifyPassword(vaultDir, password string) ([]byte, error) {
	metaBytes, err := os.ReadFile(metaPath(vaultDir))
	if err != nil {
		return nil, fmt.Errorf("vault not found")
	}
	var meta Meta
	if err := json.Unmarshal(metaBytes, &meta); err != nil {
		return nil, fmt.Errorf("corrupt meta")
	}
	key, err := deriveKey(password, meta.KDF)
	if err != nil {
		return nil, err
	}
	nonce, _ := base64.StdEncoding.DecodeString(meta.Verify.NonceB64)
	ct, _ := base64.StdEncoding.DecodeString(meta.Verify.CtB64)
	aead, _ := aeadFor(key)
	plain, err := aead.Open(nil, nonce, ct, nil)
	if err != nil || string(plain) != verifierString(meta.VaultID) {
		zeroBytes(plain)
		zeroBytes(key)
		return nil, fmt.Errorf("invalid-password")
	}
	zeroBytes(plain)
	return key, nil
}

func lanHandleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		lanWriteJSON(w, 405, map[string]string{"error": "method not allowed"})
		return
	}
	lan.Lock()
	blocked := time.Now().Before(lan.blockUntil)
	lan.Unlock()
	if blocked {
		lanWriteJSON(w, 429, map[string]string{"error": "too many tries, wait a minute"})
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&body); err != nil {
		lanWriteJSON(w, 400, map[string]string{"error": "bad request"})
		return
	}
	lan.Lock()
	vaultDir := lan.vaultDir
	lan.Unlock()
	key, err := lanVerifyPassword(vaultDir, body.Password)
	if err != nil {
		lan.Lock()
		lan.failCount++
		if lan.failCount >= 5 {
			lan.blockUntil = time.Now().Add(time.Minute)
			lan.failCount = 0
		}
		lan.Unlock()
		lanWriteJSON(w, 401, map[string]string{"error": "invalid-password"})
		return
	}
	// success: unlock the live session too (same key as desktop unlock)
	sess.Lock()
	if sess.key != nil {
		zeroBytes(sess.key)
	}
	sess.vaultDir = vaultDir
	sess.key = key
	sess.unlocked = true
	_ = readIndexLocked()
	n := len(sess.index.Files)
	sess.Unlock()
	tok := newID()
	lan.Lock()
	lan.tokens[tok] = time.Now().Add(lanTokenTTL)
	lan.failCount = 0
	// prune expired
	for t, exp := range lan.tokens {
		if time.Now().After(exp) {
			delete(lan.tokens, t)
		}
	}
	lan.Unlock()
	sendEvent("lan-login", map[string]any{"files": n})
	lanWriteJSON(w, 200, map[string]any{"token": tok, "files": n})
}

func lanHandleFiles(w http.ResponseWriter, r *http.Request) {
	if !lanCheckToken(r) {
		lanWriteJSON(w, 401, map[string]string{"error": "unauthorized"})
		return
	}
	sess.Lock()
	defer sess.Unlock()
	if !sess.unlocked {
		lanWriteJSON(w, 401, map[string]string{"error": "locked"})
		return
	}
	lanWriteJSON(w, 200, sess.index.Files)
}

func lanFindEntry(id string) *FileEntry {
	sess.Lock()
	defer sess.Unlock()
	if !sess.unlocked {
		return nil
	}
	for i := range sess.index.Files {
		if sess.index.Files[i].ID == id {
			e := sess.index.Files[i]
			return &e
		}
	}
	return nil
}

func lanDecrypt(id string) ([]byte, *FileEntry, error) {
	e := lanFindEntry(id)
	if e == nil {
		return nil, nil, fmt.Errorf("not found")
	}
	sess.Lock()
	raw, err := os.ReadFile(blobPath(sess.vaultDir, id))
	key := sess.key
	sess.Unlock()
	if err != nil {
		return nil, nil, err
	}
	plain, err := decryptBlobToPlain(key, raw, id)
	if err != nil {
		return nil, nil, fmt.Errorf("decryption failed")
	}
	return plain, e, nil
}

func lanHandleFile(w http.ResponseWriter, r *http.Request) {
	if !lanCheckToken(r) {
		lanWriteJSON(w, 401, map[string]string{"error": "unauthorized"})
		return
	}
	plain, e, err := lanDecrypt(r.URL.Query().Get("id"))
	if err != nil {
		lanWriteJSON(w, 404, map[string]string{"error": err.Error()})
		return
	}
	defer zeroBytes(plain)
	if int64(len(plain)) > MaxPreviewSize {
		lanWriteJSON(w, 413, map[string]string{"error": "too large, use stream"})
		return
	}
	w.Header().Set("Content-Type", e.Mime)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(plain)
}

func lanHandleStream(w http.ResponseWriter, r *http.Request) {
	if !lanCheckToken(r) {
		lanWriteJSON(w, 401, map[string]string{"error": "unauthorized"})
		return
	}
	plain, e, err := lanDecrypt(r.URL.Query().Get("id"))
	if err != nil {
		lanWriteJSON(w, 404, map[string]string{"error": err.Error()})
		return
	}
	defer zeroBytes(plain)
	w.Header().Set("Content-Type", e.Mime)
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("Cache-Control", "no-store")
	http.ServeContent(w, r, e.Name, time.Now(), bytes.NewReader(plain))
}

// small mobile page (no backticks inside: Go raw string + plain JS)
const lanHome = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Secure Vault</title>
<style>
body{margin:0;background:#14120f;color:#e7e2d8;font-family:system-ui,sans-serif}
.wrap{max-width:640px;margin:0 auto;padding:16px}
h1{font-size:18px;margin:4px 0 12px}h1 span{color:#e8a33d}
.card{background:#1c1a16;border:1px solid #2c2822;border-radius:10px;padding:14px;margin-bottom:10px}
input{width:100%;box-sizing:border-box;background:#14120f;border:1px solid #2c2822;color:#fff;border-radius:8px;padding:10px;font-size:15px}
button{width:100%;background:#e8a33d;border:0;border-radius:8px;padding:11px;font-size:15px;font-weight:700;margin-top:10px}
.row{display:flex;gap:8px;align-items:center;padding:10px 4px;border-bottom:1px solid #2c2822;font-size:14px}
.row .n{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.row .s{color:#8a8578;font-size:11px;font-family:monospace}
#pv img,#pv video,#pv audio{max-width:100%;border-radius:8px}
#pv iframe{width:100%;height:70vh;border:0;border-radius:8px;background:#fff}
#pv pre{white-space:pre-wrap;font-size:12px;max-height:60vh;overflow:auto}
.err{color:#e0684e;font-size:13px;min-height:18px}
.hide{display:none}
.back{background:#2c2822;color:#fff;margin-bottom:8px}
</style></head><body><div class="wrap">
<h1><span>Secure</span> Vault</h1>
<div id="login" class="card">
<div class="err" id="le"></div>
<input id="pw" type="password" placeholder="Vault password" autocomplete="off">
<button onclick="login()">Unlock</button>
</div>
<div id="main" class="hide">
<div class="card"><button class="back" onclick="showList()">&larr; Files</button><div id="pv"></div></div>
<div class="card" id="list"></div>
</div></div>
<script>
var TOK='';
function api(p,o){o=o||{};o.headers={'Content-Type':'application/json'};return fetch(p,o).then(function(r){return r.json().then(function(j){return{st:r.status,j:j}})})}
function login(){var p=document.getElementById('pw').value;api('/api/login',{method:'POST',body:JSON.stringify({password:p})}).then(function(r){if(r.st===200&&r.j.token){TOK=r.j.token;document.getElementById('login').className='hide';document.getElementById('main').className='';load()}else{document.getElementById('le').textContent=(r.j&&r.j.error)||'login failed'}})}
function sz(b){if(b<1024)return b+' B';if(b<1048576)return (b/1024).toFixed(1)+' KB';if(b<1073741824)return (b/1048576).toFixed(1)+' MB';return (b/1073741824).toFixed(2)+' GB'}
function load(){fetch('/api/files?token='+TOK).then(function(r){return r.json()}).then(function(fs){var h='';for(var i=0;i<fs.length;i++){var f=fs[i];h+='<div class="row" onclick="view(\''+f.id+'\')"><span class="n">'+f.name.replace(/</g,'&lt;')+'</span><span class="s">'+sz(f.size)+'</span></div>'}document.getElementById('list').innerHTML=h||'empty';showList()})}
var CUR=[];
function view(id){fetch('/api/files?token='+TOK).then(function(r){return r.json()}).then(function(fs){CUR=fs;var f=null;for(var i=0;i<fs.length;i++){if(fs[i].id===id)f=fs[i]}if(!f)return;var pv=document.getElementById('pv');var u='/api/stream?id='+id+'&token='+TOK;var m=f.mime||'';var html='';if(m.indexOf('image/')===0){html='<img src="'+u+'">'}else if(m.indexOf('video/')===0){html='<video src="'+u+'" controls playsinline style="width:100%">'}else if(m.indexOf('audio/')===0){html='<audio src="'+u+'" controls style="width:100%">'}else if(m==='application/pdf'){html='<iframe src="'+u+'">'}else if(m.indexOf('text/')===0){fetch('/api/file?id='+id+'&token='+TOK).then(function(r){return r.text()}).then(function(t){pv.innerHTML='<pre>'+t.replace(/</g,'&lt;').slice(0,200000)+'</pre>'})}else{html='<a style="color:#e8a33d" href="'+u+'">Download '+f.name.replace(/</g,'&lt;')+'</a>'}if(html)pv.innerHTML=html;document.getElementById('list').className='hide';pv.parentElement.className='card'})}
function showList(){document.getElementById('list').className='card';document.getElementById('pv').innerHTML=''}
document.getElementById('pw').addEventListener('keydown',function(e){if(e.key==='Enter')login()});
</script></body></html>`

func handleLanStart(req Request) {
	lan.Lock()
	if lan.running {
		port := lan.port
		lan.Unlock()
		succeed(req.ID, map[string]any{"running": true, "port": port})
		return
	}
	port := req.Port
	if port <= 0 || port > 65535 {
		port = 6767
	}
	vaultDir := req.VaultDir
	if vaultDir == "" {
		sess.Lock()
		vaultDir = sess.vaultDir
		sess.Unlock()
	}
	if vaultDir == "" {
		lan.Unlock()
		fail(req.ID, "unlock the vault on desktop first")
		return
	}
	if _, err := os.Stat(metaPath(vaultDir)); err != nil {
		lan.Unlock()
		fail(req.ID, "vault not found")
		return
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte(lanHome))
	})
	mux.HandleFunc("/api/login", lanHandleLogin)
	mux.HandleFunc("/api/files", lanHandleFiles)
	mux.HandleFunc("/api/file", lanHandleFile)
	mux.HandleFunc("/api/stream", lanHandleStream)
	ln, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil {
		lan.Unlock()
		fail(req.ID, "port busy: "+err.Error())
		return
	}
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	lan.running = true
	lan.port = port
	lan.vaultDir = vaultDir
	lan.ln = ln
	lan.srv = srv
	lan.Unlock()
	go func() {
		_ = srv.Serve(ln)
	}()
	sendEvent("lan-started", map[string]any{"port": port})
	succeed(req.ID, map[string]any{"running": true, "port": port})
}

func handleLanStop(req Request) {
	lan.Lock()
	srv, ln := lan.srv, lan.ln
	lan.running = false
	lan.srv = nil
	lan.ln = nil
	for t := range lan.tokens {
		delete(lan.tokens, t)
	}
	lan.Unlock()
	if srv != nil {
		_ = srv.Close()
	}
	if ln != nil {
		_ = ln.Close()
	}
	sendEvent("lan-stopped", map[string]any{})
	succeed(req.ID, map[string]bool{"running": false})
}

func handleLanStatus(req Request) {
	lan.Lock()
	defer lan.Unlock()
	n := 0
	for _, exp := range lan.tokens {
		if time.Now().Before(exp) {
			n++
		}
	}
	succeed(req.ID, map[string]any{"running": lan.running, "port": lan.port, "sessions": n})
}

func serve() {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 1024*1024), 64*1024*1024)
	var wg sync.WaitGroup
	for scanner.Scan() {
		line := append([]byte(nil), scanner.Bytes()...)
		var req Request
		if err := json.Unmarshal(line, &req); err != nil {
			continue
		}
		// run each request on its own goroutine so a long import
		// never blocks cancel-import / status.
		// shared state is guarded by sess.Lock + stdoutMu.
		wg.Add(1)
		go func(r Request) {
			defer wg.Done()
			dispatch(r)
		}(req)
		zeroBytes(line)
	}
	wg.Wait()
}

func dispatch(req Request) {
	switch req.Cmd {
	case "init":
		handleInit(req)
	case "unlock":
		handleUnlock(req)
	case "list":
		handleList(req)
	case "status":
		handleStatus(req)
	case "exists":
		handleExists(req)
	case "import":
		handleImport(req)
	case "import-folder":
		handleImportFolder(req)
	case "scan-folder":
		handleScanFolder(req)
	case "cancel-import":
		handleCancelImport(req)
	case "open":
		handleOpen(req)
	case "read":
		handleRead(req)
	case "stream":
		handleStream(req)
	case "stream-close":
		handleStreamClose(req)
	case "reencrypt":
		handleReencrypt(req)
	case "close":
		handleClose(req)
	case "delete":
		handleDelete(req)
	case "delete-folder":
		handleDeleteFolder(req)
	case "rename":
		handleRename(req)
	case "export":
		handleExport(req)
	case "export-folder":
		handleExportFolder(req)
	case "change-password":
		handleChangePassword(req)
	case "lan-start":
		handleLanStart(req)
	case "lan-stop":
		handleLanStop(req)
	case "lan-status":
		handleLanStatus(req)
	case "lock":
		handleLock(req)
	case "ping":
		succeed(req.ID, map[string]string{"pong": "ok"})
	default:
		fail(req.ID, "unknown command: "+req.Cmd)
	}
}

func main() {
	if len(os.Args) >= 2 && os.Args[1] == "serve" {
		serve()
		return
	}
	fmt.Println("usage: vault-core serve   (stdin/stdout JSON-Line IPC)")
}
