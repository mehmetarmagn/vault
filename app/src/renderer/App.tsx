import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  Archive, ArrowDownToLine, Check, Clock, Command, Download, File, FileText,
  Film, Fingerprint, FolderOpen, Image, KeyRound, Lock, Music, Pencil,
  Plus, Search, ShieldCheck, Trash2, Vault, X,
} from 'lucide-react'

type FileEntry = {
  id: string
  name: string
  size: number
  mime: string
  mtime: string
  format: number
}

const DEFAULT_DIR = 'C:/Users/L455C4V/Documents/secure-vault-demo'
const IDLE_LOCK_MS = 10 * 60 * 1000

function fmtSize(b: number) {
  if (b < 1024) return `${b} B`
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`
  if (b < 1024 * 1024 * 1024) return `${(b / 1024 / 1024).toFixed(1)} MB`
  return `${(b / 1024 / 1024 / 1024).toFixed(2)} GB`
}

function relTime(iso: string) {
  const d = Date.now() - new Date(iso).getTime()
  if (d < 60e3) return 'az önce'
  if (d < 3600e3) return `${Math.floor(d / 60e3)} dk`
  if (d < 86400e3) return `${Math.floor(d / 3600e3)} sa`
  return `${Math.floor(d / 86400e3)} g`
}

function fileIcon(f: FileEntry) {
  const ext = f.name.split('.').pop()?.toLowerCase() ?? ''
  const cls = 'h-4 w-4 shrink-0 text-fog'
  if (f.mime.startsWith('image/') || ['png', 'jpg', 'jpeg', 'gif', 'webp'].includes(ext))
    return <Image className={cls} />
  if (f.mime.startsWith('video/') || ['mp4', 'mkv', 'avi'].includes(ext)) return <Film className={cls} />
  if (f.mime.startsWith('audio/') || ['mp3', 'wav', 'flac'].includes(ext)) return <Music className={cls} />
  if (f.mime === 'application/pdf' || ext === 'pdf') return <FileText className={cls} />
  if (['txt', 'md'].includes(ext) || f.mime.startsWith('text/')) return <FileText className={cls} />
  if (['zip', 'rar', '7z'].includes(ext)) return <Archive className={cls} />
  return <File className={cls} />
}

type Filter = 'all' | 'img' | 'doc' | 'media' | 'other' | 'recent'
function matchFilter(f: FileEntry, flt: Filter) {
  if (flt === 'all') return true
  if (flt === 'recent') return Date.now() - new Date(f.mtime).getTime() < 7 * 864e5
  const ext = f.name.split('.').pop()?.toLowerCase() ?? ''
  const isImg = f.mime.startsWith('image/') || ['png', 'jpg', 'jpeg', 'gif', 'webp'].includes(ext)
  const isDoc = f.mime === 'application/pdf' || ['txt', 'md', 'pdf'].includes(ext) || f.mime.startsWith('text/')
  const isMedia = f.mime.startsWith('video/') || f.mime.startsWith('audio/') || ['mp4', 'mp3', 'mkv'].includes(ext)
  if (flt === 'img') return isImg
  if (flt === 'doc') return isDoc
  if (flt === 'media') return isMedia
  return !isImg && !isDoc && !isMedia
}

/* ------------------------------- uygulama ------------------------------- */

export default function App() {
  const [vaultDir, setVaultDir] = useState(DEFAULT_DIR)
  const [password, setPassword] = useState('')
  const [locked, setLocked] = useState(true)
  const [busy, setBusy] = useState(false)
  const [status, setStatus] = useState('Çekirdeğe bağlanılıyor…')
  const [files, setFiles] = useState<FileEntry[]>([])
  const [query, setQuery] = useState('')
  const [filter, setFilter] = useState<Filter>('all')
  const [sort, setSort] = useState<'date' | 'name' | 'size'>('date')
  const [openIds, setOpenIds] = useState<Set<string>>(new Set())
  const [toasts, setToasts] = useState<{ id: number; msg: string }[]>([])
  const [delTarget, setDelTarget] = useState<FileEntry | null>(null)
  const [renTarget, setRenTarget] = useState<FileEntry | null>(null)
  const [renName, setRenName] = useState('')
  const [pwModal, setPwModal] = useState(false)
  const [newPw, setNewPw] = useState('')
  const [newPw2, setNewPw2] = useState('')
  const [palOpen, setPalOpen] = useState(false)
  const toastId = useRef(0)
  const idleTimer = useRef<number | null>(null)

  const toast = useCallback((msg: string) => {
    const id = ++toastId.current
    setToasts((t) => [...t.slice(-2), { id, msg }])
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 4000)
  }, [])

  const refreshList = useCallback(async () => {
    const r = await window.vault.list()
    if (r.ok) setFiles(r.data as FileEntry[])
    else setStatus('Liste hatası: ' + r.error)
  }, [])

  const syncOpen = useCallback(async () => {
    const r = await window.vault.status()
    if (r.ok && r.data) setOpenIds(new Set(r.data.open as string[]))
  }, [])

  const doLock = useCallback(async () => {
    await window.vault.lock()
    setLocked(true); setFiles([]); setOpenIds(new Set()); setPassword(''); setPalOpen(false)
    setStatus('Kilitlendi. Anahtar bellekten silindi.')
  }, [])

  useEffect(() => {
    window.vault.onEvent((d: any) => {
      if (d?.event === 'auto-reencrypted') { toast('Değişiklik geri şifrelendi'); refreshList(); syncOpen() }
      else if (d?.event === 'file-closed') { syncOpen(); refreshList() }
      else if (d?.event === 'reencrypted') { toast('Dosya kasaya kapatıldı'); refreshList(); syncOpen() }
    })
  }, [refreshList, syncOpen, toast])

  useEffect(() => {
    window.vault.ping().then((r) => {
      setStatus(r.ok ? 'Hazır.' : 'Çekirdek cevap vermiyor: ' + r.error)
    })
  }, [])

  // Ctrl/⌘+K: komut paleti (kilit kapalıyken)
  useEffect(() => {
    if (locked) return
    const h = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        setPalOpen((v) => !v)
      }
    }
    window.addEventListener('keydown', h)
    return () => window.removeEventListener('keydown', h)
  }, [locked])

  useEffect(() => {
    if (locked) return
    const reset = () => {
      if (idleTimer.current) window.clearTimeout(idleTimer.current)
      idleTimer.current = window.setTimeout(() => { toast('10 dk hareketsizlik — kilitlendi'); doLock() }, IDLE_LOCK_MS)
    }
    reset()
    const evts = ['mousemove', 'keydown', 'click']
    evts.forEach((e) => window.addEventListener(e, reset))
    return () => {
      if (idleTimer.current) window.clearTimeout(idleTimer.current)
      evts.forEach((e) => window.removeEventListener(e, reset))
    }
  }, [locked, doLock, toast])

  async function doUnlock() {
    if (!password) { setStatus('Ana şifre gerekli.'); return }
    setBusy(true); setStatus('Anahtar türetiliyor…')
    const r = await window.vault.unlock(vaultDir, password)
    setPassword(''); setBusy(false)
    if (r.ok) {
      setLocked(false)
      setStatus(`${r.data.files} kayıt çözüldü.`)
      await refreshList(); await syncOpen()
    } else setStatus(r.error === 'invalid-password' ? 'Şifre tutmadı.' : 'Açma hatası: ' + r.error)
  }

  async function doInit() {
    if (password.length < 8) { setStatus('En az 8 karakterlik bir ana şifre seç.'); return }
    setBusy(true); setStatus('Kasa kuruluyor…')
    const r = await window.vault.init(vaultDir, password)
    setPassword(''); setBusy(false)
    if (r.ok) {
      setLocked(false); setStatus('Kasa kuruldu. Bu şifrenin yedeği yok — unutma.')
      await refreshList(); await syncOpen()
    } else setStatus('Kurulum hatası: ' + r.error)
  }

  async function doImport() {
    const r = await window.vault.importFile()
    if (r.ok && !(r.data as any)?.skipped) {
      const n = Array.isArray(r.data) ? (r.data as any[]).filter((x) => x.ok).length : 1
      toast(`${n} dosya şifrelendi`)
      await refreshList()
    }
  }

  async function doOpen(id: string) {
    setStatus('Çözülüyor…')
    const r = await window.vault.open(id)
    if (r.ok) {
      setOpenIds((s) => new Set(s).add(id))
      setStatus('Dosya açık. Kaydetmen yeterli — gerisini kasa halleder.')
    } else setStatus('Açma hatası: ' + r.error)
  }

  async function doReencrypt(id: string) {
    const r = await window.vault.reencrypt(id)
    if (r.ok) { setOpenIds((s) => { const n = new Set(s); n.delete(id); return n }); await refreshList() }
    else setStatus('Hata: ' + r.error)
  }

  async function doCloseNoSave(id: string) {
    const r = await window.vault.closeFile(id)
    if (r.ok) {
      setOpenIds((s) => { const n = new Set(s); n.delete(id); return n })
      toast('Değişiklikler atıldı, kasa aynen duruyor')
    } else setStatus('Hata: ' + r.error)
  }

  async function doDelete() {
    if (!delTarget) return
    const r = await window.vault.remove(delTarget.id)
    if (r.ok) { toast('Kayıt silindi'); setDelTarget(null); await refreshList(); await syncOpen() }
    else { setStatus('Silme hatası: ' + r.error); setDelTarget(null) }
  }

  async function doRename() {
    if (!renTarget || !renName.trim()) return
    const r = await window.vault.rename(renTarget.id, renName.trim())
    if (r.ok) { setRenTarget(null); setRenName(''); await refreshList() }
    else setStatus('Hata: ' + r.error)
  }

  async function doExport(f: FileEntry) {
    const r = await window.vault.exportFile(f.id, f.name)
    if (r.ok && !(r.data as any)?.skipped) toast('Şifresiz kopya dışa aktarıldı')
    else if (!r.ok) setStatus('Hata: ' + r.error)
  }

  async function doChangePw() {
    if (newPw.length < 8) { toast('En az 8 karakter olmalı'); return }
    if (newPw !== newPw2) { toast('İki giriş eşleşmiyor'); return }
    setBusy(true)
    const r = await window.vault.changePassword(newPw)
    setBusy(false); setNewPw(''); setNewPw2('')
    if (r.ok) { setPwModal(false); toast('Ana şifre değişti, kasa baştan mühürlendi') }
    else toast('Hata: ' + r.error)
  }

  const shown = useMemo(() => files
    .filter((f) => matchFilter(f, filter))
    .filter((f) => f.name.toLowerCase().includes(query.toLowerCase()))
    .sort((a, b) => {
      if (sort === 'name') return a.name.localeCompare(b.name, 'tr')
      if (sort === 'size') return b.size - a.size
      return new Date(b.mtime).getTime() - new Date(a.mtime).getTime()
    }), [files, filter, query, sort])

  const counts = useMemo(() => ({
    all: files.length,
    img: files.filter((f) => matchFilter(f, 'img')).length,
    doc: files.filter((f) => matchFilter(f, 'doc')).length,
    media: files.filter((f) => matchFilter(f, 'media')).length,
    other: files.filter((f) => matchFilter(f, 'other')).length,
  }), [files])

  /* ------------------------------- kilit ekranı ------------------------------- */
  if (locked) {
    return (
      <div className="flex min-h-screen bg-ink">
        <div className="hidden w-[380px] shrink-0 flex-col justify-between border-r border-line p-10 md:flex"
          style={{ backgroundImage: 'linear-gradient(rgba(255,255,255,0.025) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.025) 1px, transparent 1px)', backgroundSize: '28px 28px' }}>
          <div>
            <div className="flex items-center gap-2.5">
              <span className="relative grid h-9 w-9 place-items-center">
                <span className="spin-slow absolute inset-0 rounded-full border border-dashed border-brassdim" />
                <Vault className="h-4 w-4 text-brass" strokeWidth={1.75} />
              </span>
              <span className="font-display text-xl tracking-tight text-stone-100">Secure Vault</span>
            </div>
            <p className="mt-8 font-display text-[34px] leading-[1.15] tracking-tight text-stone-100">
              Dosyaların.<br />Kimse okumadan.
            </p>
            <div className="mt-10 space-y-4 text-[13px]">
              <div className="flex items-start gap-3">
                <Fingerprint className="mt-0.5 h-4 w-4 shrink-0 text-brass" strokeWidth={1.75} />
                <div><span className="text-stone-200">Argon2id anahtar türetme</span>
                  <div className="font-mono text-[11px] text-fog">t=3 · m=64MiB · salt 128-bit</div></div>
              </div>
              <div className="flex items-start gap-3">
                <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-brass" strokeWidth={1.75} />
                <div><span className="text-stone-200">AES-256-GCM, isimler dahil</span>
                  <div className="font-mono text-[11px] text-fog">4MB chunk · AAD zincirli</div></div>
              </div>
              <div className="flex items-start gap-3">
                <Clock className="mt-0.5 h-4 w-4 shrink-0 text-brass" strokeWidth={1.75} />
                <div><span className="text-stone-200">10 dk boşta kalınca kilit</span>
                  <div className="font-mono text-[11px] text-fog">anahtar RAM'den silinir</div></div>
              </div>
            </div>
          </div>
          <div className="font-mono text-[11px] text-fog">v1.0.0 · anahtar asla diske yazılmaz</div>
        </div>

        <div className="flex flex-1 items-center justify-center p-6">
          <div className="w-[400px] max-w-full">
            <h1 className="text-lg font-semibold text-stone-100">Kasayı aç</h1>
            <p className="mt-1 text-[13px] text-fog">Klasörü seç, ana şifreni gir. Gerisi Go çekirdekte olur.</p>
            <label className="mt-6 block text-[11px] font-medium uppercase tracking-wider text-fog">Kasa klasörü</label>
            <div className="mt-1.5 flex items-center gap-2 rounded-lg border border-line bg-panel px-3 focus-within:border-brassdim">
              <FolderOpen className="h-4 w-4 shrink-0 text-fog" strokeWidth={1.75} />
              <input value={vaultDir} onChange={(e) => setVaultDir(e.target.value)} spellCheck={false}
                className="no-ring w-full bg-transparent py-2 text-[13px] text-stone-100 placeholder:text-stone-600" />
            </div>
            <label className="mt-4 block text-[11px] font-medium uppercase tracking-wider text-fog">Ana şifre</label>
            <div className="mt-1.5 flex items-center gap-2 rounded-lg border border-line bg-panel px-3 focus-within:border-brassdim">
              <KeyRound className="h-4 w-4 shrink-0 text-fog" strokeWidth={1.75} />
              <input type="password" value={password} onChange={(e) => setPassword(e.target.value)}
                onKeyDown={(e) => { if (e.key === 'Enter') doUnlock() }} placeholder="••••••••"
                className="no-ring w-full bg-transparent py-2 text-[13px] text-stone-100 placeholder:text-stone-600" />
            </div>
            <div className="mt-5 flex gap-2">
              <button disabled={busy} onClick={doUnlock}
                className="btn flex-1 rounded-lg bg-brass px-4 py-2 text-[13px] font-semibold text-[#1a1408] hover:bg-[#f0b45a] active:bg-[#d1942f] disabled:opacity-50">
                {busy ? 'Türetiliyor…' : 'Kilidi aç'}</button>
              <button disabled={busy} onClick={doInit}
                className="btn flex-1 rounded-lg border border-line px-4 py-2 text-[13px] font-medium text-stone-300 hover:border-stone-500 disabled:opacity-50">
                Yeni kasa kur</button>
            </div>
            <p className="mt-3 min-h-[18px] font-mono text-[11px] text-fog">{status}</p>
          </div>
        </div>
      </div>
    )
  }

  /* --------------------------------- ana ekran --------------------------------- */
  const nav: [Filter, string, number][] = [
    ['all', 'Tümü', counts.all],
    ['img', 'Görseller', counts.img],
    ['doc', 'Belgeler', counts.doc],
    ['media', 'Medya', counts.media],
    ['other', 'Diğer', counts.other],
  ]

  return (
    <div className="flex min-h-screen bg-ink text-stone-200">
      <aside className="hidden w-56 shrink-0 flex-col border-r border-line bg-[#100e0b] py-4 lg:flex">
        <div className="flex items-center gap-2 px-4">
          <Vault className="h-4 w-4 text-brass" strokeWidth={1.75} />
          <span className="font-display text-[15px] tracking-tight text-stone-100">Secure Vault</span>
        </div>
        <nav className="mt-5 space-y-0.5 px-2">
          {nav.map(([k, label, n]) => (
            <button key={k} onClick={() => setFilter(k)}
              className={`navitem flex w-full items-center justify-between rounded-lg px-2.5 py-[7px] text-[13px] ${filter === k ? 'bg-panel2 text-stone-100' : 'text-fog hover:bg-panel hover:text-stone-200'}`}>
              <span>{label}</span>
              <span className="font-mono text-[11px] text-stone-500">{n}</span>
            </button>
          ))}
        </nav>
        <div className="mt-auto space-y-0.5 px-2">
          <button onClick={() => setPwModal(true)}
            className="navitem flex w-full items-center gap-2 rounded-lg px-2.5 py-[7px] text-[13px] text-fog hover:bg-panel hover:text-stone-200">
            <KeyRound className="h-3.5 w-3.5" strokeWidth={1.75} /> Şifre değiştir</button>
          <button onClick={doLock}
            className="navitem flex w-full items-center gap-2 rounded-lg px-2.5 py-[7px] text-[13px] text-fog hover:bg-panel hover:text-stone-200">
            <Lock className="h-3.5 w-3.5" strokeWidth={1.75} /> Kilitle</button>
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex h-12 shrink-0 items-center gap-2 border-b border-line px-4">
          <button onClick={() => setPalOpen(true)}
            className="btn flex h-8 flex-1 items-center gap-2 rounded-lg border border-line bg-panel px-3 text-[13px] text-stone-500 hover:border-stone-600 hover:text-stone-300">
            <Search className="h-3.5 w-3.5" strokeWidth={1.75} />
            <span>Ara, aç, kilitle…</span>
            <kbd className="ml-auto rounded border border-line bg-ink px-1.5 font-mono text-[10px]">Ctrl K</kbd>
          </button>
          <div className="flex items-center rounded-lg border border-line text-[12px]">
            {(['date', 'name', 'size'] as const).map((s) => (
              <button key={s} onClick={() => setSort(s)}
                className={`btn px-2.5 py-[7px] first:rounded-l-lg last:rounded-r-lg ${sort === s ? 'bg-panel2 text-stone-100' : 'text-fog hover:text-stone-300'}`}>
                {s === 'date' ? 'Tarih' : s === 'name' ? 'İsim' : 'Boyut'}</button>
            ))}
          </div>
          <button onClick={doImport}
            className="btn flex h-8 items-center gap-1.5 rounded-lg bg-brass px-3 text-[13px] font-semibold text-[#1a1408] hover:bg-[#f0b45a] active:bg-[#d1942f]">
            <Plus className="h-4 w-4" strokeWidth={2} /> Ekle</button>
        </header>

        <main className="flex-1 overflow-y-auto px-4 py-3">
          <div className="mb-2 flex gap-1.5 overflow-x-auto pb-1 lg:hidden">
            {nav.map(([k, label, n]) => (
              <button key={k} onClick={() => setFilter(k)}
                className={`shrink-0 rounded-lg border px-2.5 py-1.5 text-[12px] ${filter === k ? 'border-brassdim bg-panel2 text-stone-100' : 'border-line text-fog'}`}>
                {label} <span className="font-mono text-[10px] opacity-70">{n}</span></button>
            ))}
          </div>
          {shown.length === 0 ? (
            <div className="mx-auto mt-24 max-w-[420px] text-center">
              <ArrowDownToLine className="mx-auto h-8 w-8 text-stone-600" strokeWidth={1.25} />
              <p className="mt-4 font-display text-[22px] tracking-tight text-stone-100">
                {files.length === 0 ? 'Kasa boş, tertemiz.' : 'Burada aradığın yok.'}</p>
              <p className="mt-1.5 text-[13px] leading-relaxed text-fog">
                {files.length === 0
                  ? 'Ekleye bastığında dosya diske şifreli yazılır — ismi bile okunmaz.'
                  : 'Farklı bir filtre ya da arama dene.'}</p>
              {files.length === 0 && (
                <button onClick={doImport}
                  className="btn mx-auto mt-5 flex items-center gap-1.5 rounded-lg bg-brass px-4 py-2 text-[13px] font-semibold text-[#1a1408] hover:bg-[#f0b45a]">
                  <Plus className="h-4 w-4" strokeWidth={2} /> İlk dosyayı şifrele</button>
              )}
            </div>
          ) : (
            <div className="overflow-hidden rounded-[10px] border border-line">
              {shown.map((f) => {
                const open = openIds.has(f.id)
                return (
                  <div key={f.id} onDoubleClick={() => doOpen(f.id)}
                    className="rowline group flex h-10 cursor-default items-center gap-3 border-b border-line/60 bg-panel px-3 last:border-0 hover:bg-panel2">
                    {fileIcon(f)}
                    <span className="min-w-0 flex-1 truncate text-[13px] text-stone-100">
                      {f.name}
                      {open && <span className="ml-2 inline-block h-1.5 w-1.5 rounded-full bg-brass align-middle" title="Açık" />}
                    </span>
                    <span className="hidden font-mono text-[11px] text-stone-500 sm:inline">{f.id.slice(0, 8)}</span>
                    <span className="w-20 text-right font-mono text-[11px] text-fog">{fmtSize(f.size)}</span>
                    <span className="hidden w-14 text-right text-[12px] text-stone-500 md:inline">{relTime(f.mtime)}</span>
                    <span className="rowactions flex items-center gap-0.5 opacity-100 lg:opacity-0 lg:group-hover:opacity-100">
                      <IconBtn title="Aç" onClick={() => doOpen(f.id)}><FolderOpen className="h-3.5 w-3.5" strokeWidth={1.75} /></IconBtn>
                      {open && <IconBtn title="Geri şifrele" onClick={() => doReencrypt(f.id)}><Check className="h-3.5 w-3.5" strokeWidth={1.75} /></IconBtn>}
                      <IconBtn title="Dışa aktar" onClick={() => doExport(f)}><Download className="h-3.5 w-3.5" strokeWidth={1.75} /></IconBtn>
                      <IconBtn title="Adlandır" onClick={() => { setRenTarget(f); setRenName(f.name) }}><Pencil className="h-3.5 w-3.5" strokeWidth={1.75} /></IconBtn>
                      <IconBtn title="Sil" danger onClick={() => setDelTarget(f)}><Trash2 className="h-3.5 w-3.5" strokeWidth={1.75} /></IconBtn>
                    </span>
                  </div>
                )
              })}
            </div>
          )}
        </main>

        <footer className="flex h-8 shrink-0 items-center gap-4 border-t border-line px-4 font-mono text-[11px] text-stone-500">
          <span className="flex items-center gap-1.5"><ShieldCheck className="h-3 w-3 text-sage" strokeWidth={2} /> AES-256-GCM</span>
          <span>Argon2id t=3 m=64MiB</span>
          <span className="hidden sm:inline">anahtar RAM'de · diskte plaintext yok</span>
          <span className="ml-auto text-fog">{status}</span>
        </footer>
      </div>

      {palOpen && (
        <Palette
          files={files} openIds={openIds} onClose={() => setPalOpen(false)}
          onOpen={(id) => { setPalOpen(false); doOpen(id) }}
          onImport={() => { setPalOpen(false); doImport() }}
          onLock={() => { setPalOpen(false); doLock() }}
          onPw={() => { setPalOpen(false); setPwModal(true) }}
        />
      )}

      <div className="fixed bottom-10 right-4 z-50 flex flex-col gap-2">
        {toasts.map((t) => (
          <div key={t.id} className="animate-toast flex items-center gap-2 rounded-lg border border-line bg-panel2 px-3.5 py-2 text-[13px] shadow-xl">
            <Check className="h-3.5 w-3.5 text-sage" strokeWidth={2} />{t.msg}</div>
        ))}
      </div>

      {delTarget && (
        <Modal title="Kaydı sil?" onClose={() => setDelTarget(null)}>
          <p className="break-all font-mono text-[12px] text-fog">{delTarget.name}</p>
          <p className="mt-1 text-[13px] text-fog">Diskteki şifreli blok üzerine yazılarak yok edilir. Geri dönüşü yok.</p>
          <div className="mt-4 flex gap-2">
            <button onClick={doDelete} className="btn flex-1 rounded-lg bg-rust px-4 py-2 text-[13px] font-semibold text-white hover:brightness-110">Sil</button>
            <button onClick={() => setDelTarget(null)} className="btn flex-1 rounded-lg border border-line px-4 py-2 text-[13px]">Vazgeç</button>
          </div>
        </Modal>
      )}

      {renTarget && (
        <Modal title="Yeniden adlandır" onClose={() => setRenTarget(null)}>
          <input value={renName} onChange={(e) => setRenName(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Enter') doRename() }} autoFocus spellCheck={false}
            className="no-ring mt-1 w-full rounded-lg border border-line bg-ink px-3 py-2 text-[13px] focus:border-brassdim" />
          <div className="mt-4 flex gap-2">
            <button onClick={doRename} className="btn flex-1 rounded-lg bg-brass px-4 py-2 text-[13px] font-semibold text-[#1a1408] hover:bg-[#f0b45a]">Kaydet</button>
            <button onClick={() => setRenTarget(null)} className="btn flex-1 rounded-lg border border-line px-4 py-2 text-[13px]">Vazgeç</button>
          </div>
        </Modal>
      )}

      {pwModal && (
        <Modal title="Ana şifreyi değiştir" onClose={() => { setPwModal(false); setNewPw(''); setNewPw2('') }}>
          <p className="text-[13px] text-fog">Kasadaki her kayıt yeni anahtarla baştan mühürlenir. Biraz sürer.</p>
          <input type="password" value={newPw} onChange={(e) => setNewPw(e.target.value)} placeholder="Yeni şifre"
            className="no-ring mt-3 w-full rounded-lg border border-line bg-ink px-3 py-2 text-[13px] focus:border-brassdim" />
          <input type="password" value={newPw2} onChange={(e) => setNewPw2(e.target.value)} placeholder="Tekrar"
            onKeyDown={(e) => { if (e.key === 'Enter') doChangePw() }}
            className="no-ring mt-2 w-full rounded-lg border border-line bg-ink px-3 py-2 text-[13px] focus:border-brassdim" />
          <div className="mt-4 flex gap-2">
            <button disabled={busy} onClick={doChangePw} className="btn flex-1 rounded-lg bg-brass px-4 py-2 text-[13px] font-semibold text-[#1a1408] hover:bg-[#f0b45a] disabled:opacity-50">Değiştir</button>
            <button onClick={() => { setPwModal(false); setNewPw(''); setNewPw2('') }} className="btn flex-1 rounded-lg border border-line px-4 py-2 text-[13px]">Vazgeç</button>
          </div>
        </Modal>
      )}
    </div>
  )
}

/* ------------------------------ küçük parçalar ------------------------------ */

function IconBtn({ children, title, onClick, danger }: { children: React.ReactNode; title: string; onClick: () => void; danger?: boolean }) {
  return (
    <button title={title} onClick={(e) => { e.stopPropagation(); onClick() }}
      className={`btn rounded-md p-1.5 ${danger ? 'text-stone-500 hover:bg-rust/20 hover:text-rust' : 'text-stone-500 hover:bg-white/10 hover:text-stone-200'}`}>
      {children}</button>
  )
}

function Modal({ title, children, onClose }: { title: string; children: React.ReactNode; onClose: () => void }) {
  return (
    <div className="fixed inset-0 z-40 grid place-items-center bg-black/60 p-4" onClick={onClose}>
      <div className="animate-pop w-[380px] max-w-full rounded-[10px] border border-line bg-panel p-5" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between">
          <h3 className="text-[14px] font-semibold text-stone-100">{title}</h3>
          <button onClick={onClose} className="btn rounded-md p-1 text-stone-500 hover:text-stone-200">
            <X className="h-4 w-4" strokeWidth={1.75} /></button>
        </div>
        <div className="mt-2">{children}</div>
      </div>
    </div>
  )
}

function Palette({ files, openIds, onClose, onOpen, onImport, onLock, onPw }: {
  files: FileEntry[]; openIds: Set<string>; onClose: () => void
  onOpen: (id: string) => void; onImport: () => void; onLock: () => void; onPw: () => void
}) {
  const [q, setQ] = useState('')
  const [sel, setSel] = useState(0)
  const inputRef = useRef<HTMLInputElement>(null)
  useEffect(() => { inputRef.current?.focus() }, [])

  const fz = q.toLowerCase()
  const matched = files.filter((f) => f.name.toLowerCase().includes(fz)).slice(0, 6)
  const actions = [
    { label: 'Dosya ekle', hint: 'şifrele', run: onImport },
    { label: 'Ana şifreyi değiştir', hint: 'kasayı baştan mühürle', run: onPw },
    { label: 'Kasayı kilitle', hint: 'anahtarı bellekten sil', run: onLock },
  ].filter((a) => a.label.toLocaleLowerCase('tr').includes(fz))
  const total = matched.length + actions.length

  useEffect(() => { setSel(0) }, [q])
  useEffect(() => {
    const h = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
      else if (e.key === 'ArrowDown') { e.preventDefault(); setSel((s) => Math.min(s + 1, total - 1)) }
      else if (e.key === 'ArrowUp') { e.preventDefault(); setSel((s) => Math.max(s - 1, 0)) }
      else if (e.key === 'Enter') {
        if (sel < matched.length) onOpen(matched[sel].id)
        else actions[sel - matched.length]?.run()
      }
    }
    window.addEventListener('keydown', h)
    return () => window.removeEventListener('keydown', h)
  })

  let idx = -1
  return (
    <div className="fixed inset-0 z-40 bg-black/60 p-4 pt-[14vh]" onClick={onClose}>
      <div className="animate-pop mx-auto w-[560px] max-w-full overflow-hidden rounded-[10px] border border-line bg-panel shadow-2xl" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center gap-2 border-b border-line px-3.5 transition-colors focus-within:border-brassdim">
          <Command className="h-4 w-4 shrink-0 text-fog" strokeWidth={1.75} />
          <input ref={inputRef} value={q} onChange={(e) => setQ(e.target.value)} placeholder="Dosya, eylem…"
            spellCheck={false} className="no-ring w-full bg-transparent py-2.5 text-[13px] placeholder:text-stone-600" />
          <kbd className="rounded border border-line px-1.5 font-mono text-[10px] text-stone-500">esc</kbd>
        </div>
        <div className="max-h-[320px] overflow-y-auto p-1.5">
          {matched.length > 0 && <div className="px-2 pb-1 pt-1.5 text-[11px] font-medium uppercase tracking-wider text-stone-500">Dosyalar</div>}
          {matched.map((f) => {
            idx++
            const i = idx
            return (
              <button key={f.id} onClick={() => onOpen(f.id)} onMouseEnter={() => setSel(i)}
                className={`flex h-9 w-full items-center gap-2.5 rounded-lg px-2.5 text-left text-[13px] ${sel === i ? 'bg-panel2 text-stone-100' : 'text-stone-300'}`}>
                {fileIcon(f)}
                <span className="min-w-0 flex-1 truncate">{f.name}</span>
                {openIds.has(f.id) && <span className="h-1.5 w-1.5 rounded-full bg-brass" />}
                <span className="font-mono text-[11px] text-stone-500">{fmtSize(f.size)}</span>
              </button>
            )
          })}
          {actions.length > 0 && <div className="px-2 pb-1 pt-2 text-[11px] font-medium uppercase tracking-wider text-stone-500">Eylemler</div>}
          {actions.map((a) => {
            idx++
            const i = idx
            return (
              <button key={a.label} onClick={a.run} onMouseEnter={() => setSel(i)}
                className={`flex h-9 w-full items-center gap-2.5 rounded-lg px-2.5 text-left text-[13px] ${sel === i ? 'bg-panel2 text-stone-100' : 'text-stone-300'}`}>
                <span className="min-w-0 flex-1 truncate">{a.label}</span>
                <span className="text-[12px] text-stone-500">{a.hint}</span>
              </button>
            )
          })}
          {total === 0 && <div className="px-3 py-6 text-center text-[13px] text-stone-500">Eşleşen bir şey yok.</div>}
        </div>
        <div className="flex items-center gap-3 border-t border-line px-3.5 py-2 font-mono text-[10px] text-stone-500">
          <span>↑↓ gez</span><span>↵ çalıştır</span><span className="ml-auto">{total} sonuç</span>
        </div>
      </div>
    </div>
  )
}
