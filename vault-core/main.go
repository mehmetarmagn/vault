// vault-core v2: chunked AES-256-GCM + CRUD + otomatik geri şifreleme (watcher).
// IPC: stdin/stdout JSON-Line. Key sadece bu process RAM'inde.
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
	"os"
	"path/filepath"
	"sync"
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
}

type Response struct {
	ID    int `json:"id"`
	OK    bool `json:"ok"`
	Data  any `json:"data,omitempty"`
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

var stdoutMu sync.Mutex

func emit(v any) {
	stdoutMu.Lock()
	defer stdoutMu.Unlock()
	enc := json.NewEncoder(os.Stdout)
	_ = enc.Encode(v)
}

func fail(id int, msg string) { emit(Response{ID: id, OK: false, Error: msg}) }
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

// encryptFileChunked: VLT2 header + chunklar. Her chunk: nonce(12) + ctLen(4BE) + ct.
func encryptFileChunked(key, plaintext []byte, blobID string) ([]byte, error) {
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
			return nil, fmt.Errorf("chunk %d decrypt başarısız", idx)
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

func secureWipe(path string) {
	if f, err := os.OpenFile(path, os.O_WRONLY, 0600); err == nil {
		if st, err := f.Stat(); err == nil && st.Size() > 0 {
			_, _ = f.WriteAt(make([]byte, st.Size()), 0)
			_ = f.Sync()
		}
		_ = f.Close()
	}
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
	case ".pdf":
		return "application/pdf"
	case ".txt", ".md":
		return "text/plain"
	case ".mp4":
		return "video/mp4"
	case ".mp3":
		return "audio/mpeg"
	case ".zip":
		return "application/zip"
	default:
		return "application/octet-stream"
	}
}

// ---------- watcher: temp değişince otomatik geri şifrele ----------

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
					// temp silinmiş = kullanıcı kapattı, watcher'ı bitir (blob zaten şifreli duruyor)
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
				// değişmiş → otomatik geri şifrele
				sess.Lock()
				enc, err := encryptFileChunked(sess.key, data, fileID)
				zeroBytes(data)
				if err != nil {
					sess.Unlock()
					continue
				}
				_ = os.WriteFile(blobPath(sess.vaultDir, fileID), enc, 0600)
				for i := range sess.index.Files {
					if sess.index.Files[i].ID == fileID {
						sess.index.Files[i].Size = int64(len(enc))
					}
				}
				_ = writeIndexLocked()
				// yeni hash'i güncelle
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
		fail(req.ID, "vaultDir ve password gerekli")
		return
	}
	if err := os.MkdirAll(filepath.Join(req.VaultDir, "blobs"), 0700); err != nil {
		fail(req.ID, err.Error())
		return
	}
	if _, err := os.Stat(metaPath(req.VaultDir)); err == nil {
		fail(req.ID, "vault zaten var, unlock kullanın")
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
		fail(req.ID, "vaultDir ve password gerekli")
		return
	}
	metaBytes, err := os.ReadFile(metaPath(req.VaultDir))
	if err != nil {
		fail(req.ID, "vault bulunamadı, önce init edin")
		return
	}
	var meta Meta
	if err := json.Unmarshal(metaBytes, &meta); err != nil {
		fail(req.ID, "meta bozuk")
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
		fail(req.ID, "index çözülemedi: "+err.Error())
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

func handleImport(req Request) {
	sess.Lock()
	defer sess.Unlock()
	if !sess.unlocked {
		fail(req.ID, "locked")
		return
	}
	if req.Path == "" {
		fail(req.ID, "path gerekli")
		return
	}
	st, err := os.Stat(req.Path)
	if err != nil {
		fail(req.ID, err.Error())
		return
	}
	if st.Size() > MaxFileSize {
		fail(req.ID, "dosya çok büyük (limit 500MB)")
		return
	}
	data, err := os.ReadFile(req.Path)
	if err != nil {
		fail(req.ID, err.Error())
		return
	}
	id := newID()
	enc, err := encryptFileChunked(sess.key, data, id)
	plainSize := int64(len(data))
	zeroBytes(data)
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

func handleOpen(req Request) {
	// hızlı yol: zaten açıksa mevcut temp'i dön
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
		fail(req.ID, "dosya bulunamadı")
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
		fail(req.ID, "decrypt başarısız")
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
		fail(req.ID, "açık dosya yok (zaten şifreli)")
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
	enc, err := encryptFileChunked(sess.key, data, fileID)
	zeroBytes(data)
	if err != nil {
		sess.Unlock()
		fail(req.ID, err.Error())
		return
	}
	_ = os.WriteFile(blobPath(sess.vaultDir, fileID), enc, 0600)
	for i := range sess.index.Files {
		if sess.index.Files[i].ID == fileID {
			sess.index.Files[i].Size = int64(len(enc))
		}
	}
	_ = writeIndexLocked()
	sess.Unlock()
	secureWipe(tmp)
	sendEvent("reencrypted", map[string]any{"fileId": fileID})
	succeed(req.ID, map[string]string{"reencrypted": fileID})
}

func handleClose(req Request) {
	// kaydetmeden kapat: temp'i sil, blob'u aynen bırak
	sess.Lock()
	oi, ok := sess.open[req.FileID]
	if !ok {
		sess.Unlock()
		fail(req.ID, "açık dosya yok")
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
	sess.Lock()
	defer sess.Unlock()
	if !sess.unlocked {
		fail(req.ID, "locked")
		return
	}
	if o, ok := sess.open[req.FileID]; ok {
		select {
		case <-o.stopCh:
		default:
			close(o.stopCh)
		}
		secureWipe(o.tempPath)
		delete(sess.open, req.FileID)
	}
	// blob'u üzerine yazarak sil
	bp := blobPath(sess.vaultDir, req.FileID)
	if st, err := os.Stat(bp); err == nil && st.Size() > 0 {
		if f, err := os.OpenFile(bp, os.O_WRONLY, 0600); err == nil {
			_, _ = f.WriteAt(make([]byte, st.Size()), 0)
			_ = f.Close()
		}
	}
	_ = os.Remove(bp)
	kept := sess.index.Files[:0]
	for _, f := range sess.index.Files {
		if f.ID != req.FileID {
			kept = append(kept, f)
		}
	}
	sess.index.Files = kept
	_ = writeIndexLocked()
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
		fail(req.ID, "yeni isim gerekli")
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
	fail(req.ID, "dosya bulunamadı")
}

func handleExport(req Request) {
	sess.Lock()
	defer sess.Unlock()
	if !sess.unlocked {
		fail(req.ID, "locked")
		return
	}
	if req.DestPath == "" {
		fail(req.ID, "destPath gerekli")
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
		fail(req.ID, "dosya bulunamadı")
		return
	}
	raw, err := os.ReadFile(blobPath(sess.vaultDir, req.FileID))
	if err != nil {
		fail(req.ID, err.Error())
		return
	}
	plain, err := decryptBlobToPlain(sess.key, raw, req.FileID)
	if err != nil {
		fail(req.ID, "decrypt başarısız")
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
		fail(req.ID, "yeni şifre en az 8 karakter olmalı")
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
	// tüm blob'ları eski key ile çöz, yeni key ile şifrele
	for _, f := range sess.index.Files {
		raw, err := os.ReadFile(blobPath(sess.vaultDir, f.ID))
		if err != nil {
			zeroBytes(newKey)
			fail(req.ID, "blob okunamadı: "+f.Name)
			return
		}
		plain, err := decryptBlobToPlain(sess.key, raw, f.ID)
		if err != nil {
			zeroBytes(newKey)
			fail(req.ID, "decrypt başarısız: "+f.Name)
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
	// meta'yı güncelle
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
	for _, t := range openTemps {
		secureWipe(t)
	}
	succeed(req.ID, map[string]bool{"locked": true})
}

func serve() {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 1024*1024), 64*1024*1024)
	for scanner.Scan() {
		line := append([]byte(nil), scanner.Bytes()...)
		var req Request
		if err := json.Unmarshal(line, &req); err != nil {
			continue
		}
		switch req.Cmd {
		case "init":
			handleInit(req)
		case "unlock":
			handleUnlock(req)
		case "list":
			handleList(req)
		case "status":
			handleStatus(req)
		case "import":
			handleImport(req)
		case "open":
			handleOpen(req)
		case "reencrypt":
			handleReencrypt(req)
		case "close":
			handleClose(req)
		case "delete":
			handleDelete(req)
		case "rename":
			handleRename(req)
		case "export":
			handleExport(req)
		case "change-password":
			handleChangePassword(req)
		case "lock":
			handleLock(req)
		case "ping":
			succeed(req.ID, map[string]string{"pong": "ok"})
		default:
			fail(req.ID, "bilinmeyen komut: "+req.Cmd)
		}
		zeroBytes(line)
	}
}

func main() {
	if len(os.Args) >= 2 && os.Args[1] == "serve" {
		serve()
		return
	}
	fmt.Println("kullanım: vault-core serve   (stdin/stdout JSON-Line IPC)")
}
