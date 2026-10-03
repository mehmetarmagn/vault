import { useCallback, useEffect, useMemo, useRef, useState, Fragment } from 'react'
import logoMark from './assets/logo-mark.png'
import PreviewModal, { canPreview } from './Preview'
import LanModal from './LanPanel'
import {
  Archive, ArrowDownToLine, Check, ChevronDown, ChevronRight, Clock, Command, Download, Eye, EyeOff, File, FileText,
  Film, Fingerprint, Folder, FolderOpen, FolderPlus, FolderSymlink, Image, KeyRound, Lock, Music, Pencil,
  Plus, Search, ShieldCheck, Smartphone, Trash2, X,
} from 'lucide-react'

type FileEntry = {
  id: string
  name: string
  size: number
  mime: string
  mtime: string
  format: number
}

type DirNode = {
  name: string
  full: string
  dirs: DirNode[]
  files: FileEntry[]
  totalFiles: number
  totalSize: number
}

type TaskProg = {
  op: string
  phase: string
  root: string
  done: number
  total: number
  current: string
  bytesDone: number
  bytesTotal: number
  startedAt: number
}

function opVerb(op: string) {
  if (op === 'export') return 'Exporting'
  if (op === 'delete') return 'Deleting'
  return 'Encrypting'
}

const IDLE_LOCK_MS = 10 * 60 * 1000

function friendlyError(e?: string) {
  if (!e) return 'Unknown error.'
  if (e === 'invalid-password') return 'Wrong password.'
  if (e === 'locked') return 'Unlock the vault first.'
  if (e === 'go-timeout') return 'Core did not answer within 90s.'
  if (e.includes('Access is denied') || e.includes('permission denied'))
    return 'Windows denied writing to that folder. Run as a normal user; the vault lives in its automatic location.'
  if (e.includes('could not create vault folder')) return e
  return e
}

function pwScore(pw: string) {
  let s = 0
  if (pw.length >= 8) s++
  if (pw.length >= 12) s++
  if (/[A-ZĞÜŞİÖÇ]/.test(pw) && /[a-zğüşiöç]/.test(pw)) s++
  if (/\d/.test(pw)) s++
  if (/[^A-Za-z0-9ğüşiöçĞÜŞİÖÇ]/.test(pw)) s++
  return Math.min(s, 4)
}

function fmtSize(b: number) {
  if (b < 1024) return `${b} B`
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`
  if (b < 1024 * 1024 * 1024) return `${(b / 1024 / 1024).toFixed(1)} MB`
  return `${(b / 1024 / 1024 / 1024).toFixed(2)} GB`
}

function fmtDur(sec: number | null) {
  if (sec === null || !isFinite(sec)) return '—'
  const s = Math.max(0, Math.round(sec))
  return `${String(Math.floor(s / 60)).padStart(2, '0')}:${String(s % 60).padStart(2, '0')}`
}

function relTime(iso: string) {
  const d = Date.now() - new Date(iso).getTime()
  if (d < 60e3) return 'just now'
  if (d < 3600e3) return `${Math.floor(d / 60e3)}m`
  if (d < 86400e3) return `${Math.floor(d / 3600e3)}h`
  return `${Math.floor(d / 86400e3)}d`
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

  /* ------------------------------- app ------------------------------- */

export default function App() {
  const [vaultDir, setVaultDir] = useState('')
  const [vaultExists, setVaultExists] = useState<boolean | null>(null)
  const [password, setPassword] = useState('')
  const [showPw, setShowPw] = useState(false)
  const [locked, setLocked] = useState(true)
  const [busy, setBusy] = useState(false)
  const [status, setStatus] = useState('Connecting to core…')
  const [files, setFiles] = useState<FileEntry[]>([])
  const [query, setQuery] = useState('')
  const [filter, setFilter] = useState<Filter>('all')
  const [sort, setSort] = useState<'date' | 'name' | 'size'>('date')
  const [openIds, setOpenIds] = useState<Set<string>>(new Set())
  const [toasts, setToasts] = useState<{ id: number; msg: string }[]>([])
  const [importProg, setImportProg] = useState<TaskProg | null>(null)
  const [cancelling, setCancelling] = useState(false)
  const [nowTick, setNowTick] = useState(0)
  const [delTarget, setDelTarget] = useState<FileEntry | null>(null)
  const [folderDelTarget, setFolderDelTarget] = useState<string | null>(null)
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set())
  const [renTarget, setRenTarget] = useState<FileEntry | null>(null)
  const [renName, setRenName] = useState('')
  const [previewFile, setPreviewFile] = useState<FileEntry | null>(null)
  const [lanOpen, setLanOpen] = useState(false)
  const [deleting, setDeleting] = useState(false)
  const [deletingFolder, setDeletingFolder] = useState(false)
  const [importReport, setImportReport] = useState<{
    imported: number; skipped: { path: string; reason: string }[]; skippedExtra: number
    emptyDirs: string[]; emptyExtra: number
  } | null>(null)
  const [pendingImport, setPendingImport] = useState<{
    root: string; total: number; bytesTotal: number
    skipped: { path: string; reason: string }[]; skippedExtra: number
    emptyDirs: string[]; emptyExtra: number
  } | null>(null)
  const [confirming, setConfirming] = useState(false)

  const LARGE_FOLDER_FILES = 2000
  const LARGE_FOLDER_BYTES = 2 * 1024 * 1024 * 1024
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
    else setStatus('List failed: ' + r.error)
  }, [])

  const syncOpen = useCallback(async () => {
    const r = await window.vault.status()
    if (r.ok && r.data) setOpenIds(new Set(r.data.open as string[]))
  }, [])

  const doLock = useCallback(async () => {
    await window.vault.lock()
    setLocked(true); setFiles([]); setOpenIds(new Set()); setPassword(''); setPalOpen(false)
    setStatus('Locked. Key wiped from memory.')
  }, [])

  useEffect(() => {
    window.vault.onEvent((d: any) => {
      if (d?.event === 'auto-reencrypted') { toast('Change sealed back in'); refreshList(); syncOpen() }
      else if (d?.event === 'file-closed') { syncOpen(); refreshList() }
      else if (d?.event === 'reencrypted') { toast('File sealed into the vault'); refreshList(); syncOpen() }
      else if (d?.event === 'import-progress') {
        const op = (d.op as string) || 'import'
        const ph = d.phase as string
        if (ph === 'scan' || ph === 'start') {
          setCancelling(false)
          setImportProg((p) => ({
            op, phase: ph, root: d.root || '',
            done: 0, total: d.total || 0, current: '',
            bytesDone: 0, bytesTotal: d.bytesTotal || 0,
            startedAt: ph === 'scan' || !p || p.op !== op ? Date.now() : p.startedAt,
          }))
        } else if (ph === 'progress' || ph === 'done') {
          setImportProg((p) => p ? {
            ...p, op, phase: ph,
            done: d.done ?? p.done, total: d.total ?? p.total,
            current: d.current ?? '', bytesDone: d.bytesDone ?? p.bytesDone, bytesTotal: d.bytesTotal ?? p.bytesTotal,
          } : p)
          if (ph === 'done') { refreshList(); syncOpen() }
        }
      }
    })
  }, [refreshList, syncOpen, toast])

  useEffect(() => {
    if (!importProg) return
    const t = window.setInterval(() => setNowTick(Date.now()), 500)
    return () => window.clearInterval(t)
  }, [importProg !== null])

  useEffect(() => {
    let cancelled = false
    ;(async () => {
      const p = await window.vault.ping()
      if (cancelled) return
      if (!p.ok) { setStatus('Core is not responding: ' + friendlyError(p.error)); return }
      try {
        const d = await window.vault.defaultDir()
        const dir = (d.ok && (d.data as any)?.path) ? (d.data as any).path as string : ''
        if (cancelled) return
        if (dir) {
          setVaultDir(dir)
          const ex = await window.vault.exists(dir)
          if (cancelled) return
          const exists = !!(ex.ok && (ex.data as any)?.exists)
          setVaultExists(exists)
          setStatus(exists ? 'Ready. Enter your password to open the vault.' : 'No vault yet. Pick a password and it sets itself up.')
        } else {
          setStatus('Ready.')
        }
      } catch {
        setStatus('Ready.')
      }
    })()
    return () => { cancelled = true }
  }, [])

  async function refreshExists(dir?: string) {
    const d = dir ?? vaultDir
    if (!d) return
    const ex = await window.vault.exists(d)
    if (ex.ok) setVaultExists(!!(ex.data as any)?.exists)
  }

  async function pickDir() {
    const r = await window.vault.selectDir()
    if (r.ok && (r.data as any)?.path) {
      setVaultDir((r.data as any).path)
      await refreshExists((r.data as any).path)
    }
  }

  // Ctrl/Cmd+K: command palette (while unlocked)
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
      idleTimer.current = window.setTimeout(() => { toast('Locked after 10 idle minutes'); doLock() }, IDLE_LOCK_MS)
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
    if (!password) { setStatus('Master password required.'); return }
    if (!vaultDir) { setStatus('Vault location is warming up, one second.'); return }
    setBusy(true); setStatus('Deriving key…')
    const r = await window.vault.unlock(vaultDir, password)
    setPassword(''); setBusy(false)
    if (r.ok) {
      setLocked(false)
      setStatus(`${r.data.files} entries decrypted.`)
      await refreshList(); await syncOpen()
    } else setStatus(friendlyError(r.error))
  }

  async function doInit() {
    if (password.length < 8) { setStatus('Pick a master password of at least 8 characters.'); return }
    if (!vaultDir) { setStatus('Vault location is warming up, one second.'); return }
    setBusy(true); setStatus('Setting up vault…')
    const r = await window.vault.init(vaultDir, password)
    setPassword(''); setBusy(false)
    if (r.ok) {
      setLocked(false); setVaultExists(true)
      setStatus('Vault created. There is no backup of this password — keep it safe.')
      await refreshList(); await syncOpen()
    } else setStatus(friendlyError(r.error))
  }

  async function doImport() {
    const r = await window.vault.importFile()
    if (r.ok && !(r.data as any)?.skipped) {
      const n = Array.isArray(r.data) ? (r.data as any[]).filter((x) => x.ok).length : 1
      toast(`${n} ${n === 1 ? 'file' : 'files'} encrypted`)
      await refreshList()
    }
  }

  async function doImportFolder() {
    setImportProg({
      op: 'import', phase: 'scan', root: '…', done: 0, total: 0, current: '',
      bytesDone: 0, bytesTotal: 0, startedAt: Date.now(),
    })
    const r = await window.vault.importFolder() // folder picker + scan
    if ((r.data as any)?.skipped) { setImportProg(null); return }
    if (!r.ok) { setImportProg(null); setStatus('Error: ' + friendlyError(r.error)); return }
    const d = r.data as any
    const big = (d?.total ?? 0) > LARGE_FOLDER_FILES || (d?.bytesTotal ?? 0) > LARGE_FOLDER_BYTES
    if (!big) {
      await runImportConfirm()
    } else {
      setImportProg(null)
      setPendingImport({
        root: d?.root ?? '', total: d?.total ?? 0, bytesTotal: d?.bytesTotal ?? 0,
        skipped: Array.isArray(d?.skipped) ? d.skipped : [], skippedExtra: d?.skippedExtra ?? 0,
        emptyDirs: Array.isArray(d?.emptyDirs) ? d.emptyDirs : [], emptyExtra: d?.emptyExtra ?? 0,
      })
    }
  }

  async function runImportConfirm() {
    setPendingImport(null)
    setConfirming(true)
    const r = await window.vault.confirmImportFolder()
    setConfirming(false)
    setImportProg(null); setCancelling(false)
    if (r.ok) {
      const d = r.data as any
      if (d?.cancelled) {
        toast('Transfer cancelled, received files stay in the vault')
      } else {
        const n = Array.isArray(d?.imported) ? d.imported.length : 0
        const s = Array.isArray(d?.skipped) ? d.skipped : []
        const e = Array.isArray(d?.emptyDirs) ? d.emptyDirs : []
        if (s.length === 0 && (d?.skippedExtra ?? 0) === 0 && e.length === 0 && (d?.emptyExtra ?? 0) === 0) {
          toast(`${n} ${n === 1 ? 'file' : 'files'} encrypted`)
        } else {
          setImportReport({
            imported: n, skipped: s, skippedExtra: d?.skippedExtra ?? 0,
            emptyDirs: e, emptyExtra: d?.emptyExtra ?? 0,
          })
        }
      }
      await refreshList()
    } else setStatus('Error: ' + friendlyError(r.error))
  }

  async function doCancelImport() {
    setCancelling(true)
    await window.vault.cancelImport()
  }

  async function doExportFolder(prefix: string) {
    const r = await window.vault.exportFolder(prefix)
    setImportProg(null); setCancelling(false)
    if (r.ok && !(r.data as any)?.skipped) {
      const d = r.data as any
      toast(d?.cancelled ? 'Export cancelled' : `${d?.exported ?? ''} files exported`.trim())
      await refreshList()
    } else if (!r.ok) setStatus('Error: ' + friendlyError(r.error))
  }

  async function doDeleteFolder() {
    if (!folderDelTarget || deletingFolder) return
    setDeletingFolder(true)
    const r = await window.vault.deleteFolder(folderDelTarget)
    setDeletingFolder(false)
    setImportProg(null); setCancelling(false)
    if (r.ok) {
      const d = r.data as any
      toast((d as any)?.note === 'already gone' ? 'Folder was already gone'
        : d?.cancelled ? 'Deletion cancelled, removed entries are gone' : 'Folder deleted')
      setFolderDelTarget(null); await refreshList(); await syncOpen()
    }     else { setStatus('Delete failed: ' + friendlyError(r.error)); setFolderDelTarget(null) }
  }

  function toggleGroup(prefix: string) {
    setCollapsed((s) => { const n = new Set(s); if (n.has(prefix)) n.delete(prefix); else n.add(prefix); return n })
  }

  const renderDir = (d: DirNode, depth: number) => {
    const col = collapsed.has(d.full)
    return (
      <Fragment key={d.full}>
        <div className="flex h-10 items-center gap-2 border-b border-line/60 bg-panel2/60 pr-3"
          style={{ paddingLeft: 12 + depth * 18 }}>
          <button onClick={() => toggleGroup(d.full)}
            className="btn flex min-w-0 flex-1 items-center gap-2.5 text-left">
            {col
              ? <ChevronRight className="h-3.5 w-3.5 shrink-0 text-stone-500" strokeWidth={1.75} />
              : <ChevronDown className="h-3.5 w-3.5 shrink-0 text-stone-500" strokeWidth={1.75} />}
            <Folder className="h-4 w-4 shrink-0 text-brass" strokeWidth={1.75} />
            <span className="min-w-0 flex-1 truncate text-[13px] font-medium text-stone-100">{d.name}</span>
                      <span className="shrink-0 font-mono text-[11px] text-stone-500">
                        {d.totalFiles} {d.totalFiles === 1 ? 'file' : 'files'} · {fmtSize(d.totalSize)}</span>
          </button>
          <span className="flex shrink-0 items-center gap-0.5">
                      <IconBtn title="Export folder" onClick={() => doExportFolder(d.full)}><Download className="h-3.5 w-3.5" strokeWidth={1.75} /></IconBtn>
                      <IconBtn title="Delete folder" danger onClick={() => setFolderDelTarget(d.full)}><Trash2 className="h-3.5 w-3.5" strokeWidth={1.75} /></IconBtn>
          </span>
        </div>
        {!col && d.dirs.map((c) => renderDir(c, depth + 1))}
        {!col && d.files.map((f) => renderRow(f, f.name.slice(d.full.length + 1), depth + 1))}
      </Fragment>
    )
  }

  const renderRow = (f: FileEntry, label: string, depth = 0) => {
    const open = openIds.has(f.id)
    return (
      <div key={f.id} onDoubleClick={() => doOpen(f.id)}
        className="rowline group flex h-10 cursor-default items-center gap-3 border-b border-line/60 bg-panel pr-3 hover:bg-panel2"
        style={{ paddingLeft: 12 + depth * 18 }}>
        {fileIcon(f)}
        <span className="min-w-0 flex-1 truncate text-[13px] text-stone-100" title={f.name}>
          {label}
                      {open && <span className="ml-2 inline-block h-1.5 w-1.5 rounded-full bg-brass align-middle" title="Open" />}
        </span>
        <span className="hidden font-mono text-[11px] text-stone-500 sm:inline">{f.id.slice(0, 8)}</span>
        <span className="w-20 text-right font-mono text-[11px] text-fog">{fmtSize(f.size)}</span>
        <span className="hidden w-14 text-right text-[12px] text-stone-500 md:inline">{relTime(f.mtime)}</span>
        <span className="rowactions flex items-center gap-0.5 opacity-100 lg:opacity-0 lg:group-hover:opacity-100">
          {canPreview(f) && <IconBtn title="Preview inside the vault" onClick={() => setPreviewFile(f)}><Eye className="h-3.5 w-3.5" strokeWidth={1.75} /></IconBtn>}
          <IconBtn title="Open" onClick={() => doOpen(f.id)}><FolderOpen className="h-3.5 w-3.5" strokeWidth={1.75} /></IconBtn>
          {open && <IconBtn title="Seal back" onClick={() => doReencrypt(f.id)}><Check className="h-3.5 w-3.5" strokeWidth={1.75} /></IconBtn>}
          <IconBtn title="Export" onClick={() => doExport(f)}><Download className="h-3.5 w-3.5" strokeWidth={1.75} /></IconBtn>
          <IconBtn title="Rename" onClick={() => { setRenTarget(f); setRenName(f.name) }}><Pencil className="h-3.5 w-3.5" strokeWidth={1.75} /></IconBtn>
          <IconBtn title="Delete" danger onClick={() => setDelTarget(f)}><Trash2 className="h-3.5 w-3.5" strokeWidth={1.75} /></IconBtn>
        </span>
      </div>
    )
  }

  async function doOpen(id: string) {
    setStatus('Decrypting…')
    const r = await window.vault.open(id)
    if (r.ok) {
      setOpenIds((s) => new Set(s).add(id))
      setStatus('File is open. Just save — the vault handles the rest.')
    } else setStatus('Open failed: ' + r.error)
  }

  async function doReencrypt(id: string) {
    const r = await window.vault.reencrypt(id)
    if (r.ok) { setOpenIds((s) => { const n = new Set(s); n.delete(id); return n }); await refreshList() }
    else setStatus('Error: ' + r.error)
  }

  async function doCloseNoSave(id: string) {
    const r = await window.vault.closeFile(id)
    if (r.ok) {
      setOpenIds((s) => { const n = new Set(s); n.delete(id); return n })
      toast('Changes discarded, vault untouched')
    } else setStatus('Error: ' + r.error)
  }

  async function doDelete() {
    if (!delTarget || deleting) return
    setDeleting(true)
    const r = await window.vault.remove(delTarget.id)
    setDeleting(false)
    if (r.ok) {
      toast((r.data as any)?.note === 'already gone' ? 'Entry was already gone' : 'Entry deleted')
      setDelTarget(null); await refreshList(); await syncOpen()
    } else { setStatus('Delete failed: ' + friendlyError(r.error)); setDelTarget(null) }
  }

  async function doRename() {
    if (!renTarget || !renName.trim()) return
    const r = await window.vault.rename(renTarget.id, renName.trim())
    if (r.ok) { setRenTarget(null); setRenName(''); await refreshList() }
    else setStatus('Error: ' + r.error)
  }

  async function doExport(f: FileEntry) {
    const r = await window.vault.exportFile(f.id, f.name)
    if (r.ok && !(r.data as any)?.skipped) toast('Decrypted copy exported')
    else if (!r.ok) setStatus('Error: ' + r.error)
  }

  async function doChangePw() {
    if (newPw.length < 8) { toast('At least 8 characters'); return }
    if (newPw !== newPw2) { toast("Passwords don't match"); return }
    setBusy(true)
    const r = await window.vault.changePassword(newPw)
    setBusy(false); setNewPw(''); setNewPw2('')
    if (r.ok) { setPwModal(false); toast('Master password changed, vault resealed') }
    else toast('Error: ' + r.error)
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

  // iç içe ağaç: "a/b/c.txt" -> a > b > c.txt (yapı korunur)
  const tree = useMemo(() => {
    type M = { dirs: Map<string, M>; files: FileEntry[] }
    const mk = (): M => ({ dirs: new Map(), files: [] })
    const root: M = mk()
    for (const f of shown) {
      const parts = f.name.split('/')
      let cur = root
      for (let i = 0; i < parts.length - 1; i++) {
        let n = cur.dirs.get(parts[i])
        if (!n) { n = mk(); cur.dirs.set(parts[i], n) }
        cur = n
      }
      cur.files.push(f)
    }
    const visDir = (d: DirNode): boolean => d.files.length > 0 || d.dirs.some(visDir)
    const conv = (name: string, full: string, m: M): DirNode => {
      const dirs = [...m.dirs.entries()]
        .sort((a, b) => a[0].localeCompare(b[0], 'tr'))
        .map(([n, mm]) => conv(n, full ? `${full}/${n}` : n, mm))
        .filter(visDir)
      let tf = m.files.length, ts = 0
      for (const f of m.files) ts += f.size
      for (const d of dirs) { tf += d.totalFiles; ts += d.totalSize }
      return { name, full, dirs, files: m.files, totalFiles: tf, totalSize: ts }
    }
    const dirs = [...root.dirs.entries()]
      .sort((a, b) => a[0].localeCompare(b[0], 'tr'))
      .map(([n, mm]) => conv(n, n, mm))
      .filter(visDir)
    return { rootFiles: root.files, dirs }
  }, [shown])

  const progStats = useMemo(() => {
    void nowTick
    if (!importProg || importProg.phase === 'scan' || !importProg.total) return null
    const elapsed = Math.max(0.5, (Date.now() - importProg.startedAt) / 1000)
    const frac = importProg.bytesTotal > 0
      ? importProg.bytesDone / importProg.bytesTotal
      : importProg.done / importProg.total
    const speed = importProg.bytesDone / elapsed
    const eta = speed > 1 && importProg.bytesTotal > 0
      ? (importProg.bytesTotal - importProg.bytesDone) / speed : null
    return { frac: Math.min(1, Math.max(0, frac)), speed, eta, elapsed }
  }, [importProg, nowTick])

  /* ------------------------------- lock screen ------------------------------- */
  if (locked) {
    return (
      <div className="flex min-h-screen bg-ink">
        <div className="hidden w-[380px] shrink-0 flex-col justify-between border-r border-line p-10 md:flex"
          style={{ backgroundImage: 'linear-gradient(rgba(255,255,255,0.025) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.025) 1px, transparent 1px)', backgroundSize: '28px 28px' }}>
          <div>
            <div className="flex items-center gap-2.5">
              <img src={logoMark} alt="Secure Vault" className="h-9 w-9 object-contain" />
              <span className="font-display text-xl tracking-tight text-stone-100">Secure Vault</span>
            </div>
            <p className="mt-8 font-display text-[34px] leading-[1.15] tracking-tight text-stone-100">
              Your files.<br />No one else's business.
            </p>
            <div className="mt-10 space-y-4 text-[13px]">
              <div className="flex items-start gap-3">
                <Fingerprint className="mt-0.5 h-4 w-4 shrink-0 text-brass" strokeWidth={1.75} />
                <div><span className="text-stone-200">Argon2id key derivation</span>
                  <div className="font-mono text-[11px] text-fog">t=3 · m=64MiB · 128-bit salt</div></div>
              </div>
              <div className="flex items-start gap-3">
                <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-brass" strokeWidth={1.75} />
                <div><span className="text-stone-200">AES-256-GCM, filenames included</span>
                  <div className="font-mono text-[11px] text-fog">4MB chunks · chained AAD</div></div>
              </div>
              <div className="flex items-start gap-3">
                <Clock className="mt-0.5 h-4 w-4 shrink-0 text-brass" strokeWidth={1.75} />
                <div><span className="text-stone-200">Auto-locks after 10 idle minutes</span>
                  <div className="font-mono text-[11px] text-fog">key wiped from RAM</div></div>
              </div>
            </div>
          </div>
          <div className="font-mono text-[11px] text-fog">v1.0.0 · the key never touches disk</div>
        </div>

        <div className="flex flex-1 items-center justify-center p-6">
          <div className="w-[400px] max-w-full">
            <div className="flex items-center gap-2">
              <h1 className="text-lg font-semibold text-stone-100">
                {vaultExists === false ? 'Create vault' : 'Unlock vault'}
              </h1>
              {vaultExists !== null && (
                <span className={`rounded-full border px-2 py-0.5 font-mono text-[10px] ${vaultExists ? 'border-sage/40 text-sage' : 'border-brassdim/60 text-brass'}`}>
                  {vaultExists ? 'vault found' : 'first setup'}
                </span>
              )}
            </div>
            <p className="mt-1 text-[13px] text-fog">
              {vaultExists === false
                ? 'Pick a password and the app handles the rest. No folders to manage.'
                : 'Enter your password to open the vault. The key only ever lives in memory.'}
            </p>

            <div className="mt-5 rounded-lg border border-line bg-panel px-3 py-2.5">
              <div className="flex items-center gap-2">
                <FolderSymlink className="h-4 w-4 shrink-0 text-fog" strokeWidth={1.75} />
                <span className="min-w-0 flex-1 truncate font-mono text-[11px] text-stone-300" title={vaultDir || 'warming up…'}>
                  {vaultDir || 'resolving vault location…'}
                </span>
              </div>
              <div className="mt-2 flex gap-2">
                <button onClick={() => vaultDir && window.vault.reveal(vaultDir)}
                  className="btn rounded-md px-2 py-1 text-[12px] text-fog hover:bg-white/5 hover:text-stone-200">
                  Reveal location</button>
                <button onClick={pickDir}
                  className="btn rounded-md px-2 py-1 text-[12px] text-fog hover:bg-white/5 hover:text-stone-200">
                  Advanced: use another folder</button>
              </div>
              <p className="mt-1.5 text-[11px] leading-relaxed text-stone-500">
                The vault is kept automatically. Export your files anytime to move them elsewhere.
              </p>
            </div>

            <label className="mt-4 block text-[11px] font-medium uppercase tracking-wider text-fog">Master password</label>
            <div className="mt-1.5 flex items-center gap-2 rounded-lg border border-line bg-panel px-3 focus-within:border-brassdim">
              <KeyRound className="h-4 w-4 shrink-0 text-fog" strokeWidth={1.75} />
              <input type={showPw ? 'text' : 'password'} value={password} onChange={(e) => setPassword(e.target.value)}
                onKeyDown={(e) => { if (e.key === 'Enter') vaultExists === false ? doInit() : doUnlock() }} placeholder="••••••••"
                className="no-ring w-full bg-transparent py-2 text-[13px] text-stone-100 placeholder:text-stone-600" />
              <button onClick={() => setShowPw((v) => !v)} title={showPw ? 'Hide' : 'Show'}
                className="btn shrink-0 rounded-md p-1 text-stone-500 hover:text-stone-200">
                {showPw ? <EyeOff className="h-4 w-4" strokeWidth={1.75} /> : <Eye className="h-4 w-4" strokeWidth={1.75} />}</button>
            </div>
            {vaultExists === false && password.length > 0 && (
              <div className="mt-2 flex items-center gap-1.5">
                {[0, 1, 2, 3].map((i) => (
                  <span key={i} className={`h-1 flex-1 rounded-full ${i <= pwScore(password) ? 'bg-brass' : 'bg-white/10'}`} />
                ))}
                <span className="ml-1 font-mono text-[10px] text-fog">
                  {pwScore(password) <= 1 ? 'weak' : pwScore(password) === 2 ? 'fair' : 'strong'}</span>
              </div>
            )}
            <div className="mt-5 flex gap-2">
              {vaultExists === false ? (
                <>
                  <button disabled={busy || !vaultDir} onClick={doInit}
                    className="btn flex-1 rounded-lg bg-brass px-4 py-2 text-[13px] font-semibold text-[#1a1408] hover:bg-[#f0b45a] active:bg-[#d1942f] disabled:opacity-50">
                    {busy ? 'Setting up…' : 'Create vault'}</button>
                  <button disabled={busy} onClick={() => refreshExists()}
                    className="btn rounded-lg border border-line px-4 py-2 text-[13px] font-medium text-stone-300 hover:border-stone-500 disabled:opacity-50">
                    Retry</button>
                </>
              ) : (
                <>
                  <button disabled={busy || !vaultDir} onClick={doUnlock}
                    className="btn flex-1 rounded-lg bg-brass px-4 py-2 text-[13px] font-semibold text-[#1a1408] hover:bg-[#f0b45a] active:bg-[#d1942f] disabled:opacity-50">
                    {busy ? 'Deriving…' : 'Unlock'}</button>
                  <button disabled={busy || !vaultDir} onClick={doInit}
                    title="Wipes the current vault and starts over"
                    className="btn flex-1 rounded-lg border border-line px-4 py-2 text-[13px] font-medium text-stone-300 hover:border-stone-500 disabled:opacity-50">
                    Start over</button>
                </>
              )}
            </div>
            <p className="mt-3 min-h-[18px] font-mono text-[11px] text-fog">{status}</p>
          </div>
        </div>
      </div>
    )
  }

  /* --------------------------------- main view --------------------------------- */
  const nav: [Filter, string, number][] = [
    ['all', 'All', counts.all],
    ['img', 'Images', counts.img],
    ['doc', 'Documents', counts.doc],
    ['media', 'Media', counts.media],
    ['other', 'Other', counts.other],
  ]

  return (
    <div className="flex min-h-screen bg-ink text-stone-200">
      <aside className="hidden w-56 shrink-0 flex-col border-r border-line bg-[#100e0b] py-4 lg:flex">
        <div className="flex items-center gap-2 px-4">
          <img src={logoMark} alt="Secure Vault" className="h-5 w-5 object-contain" />
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
          <button onClick={() => setLanOpen(true)}
            className="navitem flex w-full items-center gap-2 rounded-lg px-2.5 py-[7px] text-[13px] text-fog hover:bg-panel hover:text-stone-200">
            <Smartphone className="h-3.5 w-3.5" strokeWidth={1.75} /> Phone access</button>
          <button onClick={() => setPwModal(true)}
            className="navitem flex w-full items-center gap-2 rounded-lg px-2.5 py-[7px] text-[13px] text-fog hover:bg-panel hover:text-stone-200">
            <KeyRound className="h-3.5 w-3.5" strokeWidth={1.75} /> Change password</button>
          <button onClick={doLock}
            className="navitem flex w-full items-center gap-2 rounded-lg px-2.5 py-[7px] text-[13px] text-fog hover:bg-panel hover:text-stone-200">
            <Lock className="h-3.5 w-3.5" strokeWidth={1.75} /> Lock</button>
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex h-12 shrink-0 items-center gap-2 border-b border-line px-4">
          <button onClick={() => setPalOpen(true)}
            className="btn flex h-8 flex-1 items-center gap-2 rounded-lg border border-line bg-panel px-3 text-[13px] text-stone-500 hover:border-stone-600 hover:text-stone-300">
            <Search className="h-3.5 w-3.5" strokeWidth={1.75} />
            <span>Search, open, lock…</span>
            <kbd className="ml-auto rounded border border-line bg-ink px-1.5 font-mono text-[10px]">Ctrl K</kbd>
          </button>
          <div className="flex items-center rounded-lg border border-line text-[12px]">
            {(['date', 'name', 'size'] as const).map((s) => (
              <button key={s} onClick={() => setSort(s)}
                className={`btn px-2.5 py-[7px] first:rounded-l-lg last:rounded-r-lg ${sort === s ? 'bg-panel2 text-stone-100' : 'text-fog hover:text-stone-300'}`}>
                {s === 'date' ? 'Date' : s === 'name' ? 'Name' : 'Size'}</button>
            ))}
          </div>
          <button onClick={doImportFolder} title="Encrypt a folder with its tree"
            className="btn flex h-8 items-center gap-1.5 rounded-lg border border-line px-3 text-[13px] font-medium text-stone-300 hover:border-stone-500 hover:text-stone-100">
            <FolderPlus className="h-4 w-4" strokeWidth={1.75} /> Folder</button>
          <button onClick={doImport}
            className="btn flex h-8 items-center gap-1.5 rounded-lg bg-brass px-3 text-[13px] font-semibold text-[#1a1408] hover:bg-[#f0b45a] active:bg-[#d1942f]">
            <Plus className="h-4 w-4" strokeWidth={2} /> Add</button>
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
                {files.length === 0 ? 'Vault is empty.' : 'Nothing matches.'}</p>
              <p className="mt-1.5 text-[13px] leading-relaxed text-fog">
                {files.length === 0
                  ? 'Hit Add and the file lands on disk encrypted — not even its name stays readable.'
                  : 'Try another filter or search.'}</p>
              {files.length === 0 && (
                <button onClick={doImport}
                  className="btn mx-auto mt-5 flex items-center gap-1.5 rounded-lg bg-brass px-4 py-2 text-[13px] font-semibold text-[#1a1408] hover:bg-[#f0b45a]">
                  <Plus className="h-4 w-4" strokeWidth={2} /> Encrypt your first file</button>
              )}
            </div>
          ) : (
            <div className="overflow-hidden rounded-[10px] border border-line">
              {tree.dirs.map((d) => renderDir(d, 0))}
              {tree.rootFiles.map((f) => renderRow(f, f.name, 0))}            </div>
          )}
        </main>

        <footer className="flex h-8 shrink-0 items-center gap-4 border-t border-line px-4 font-mono text-[11px] text-stone-500">
          <span className="flex items-center gap-1.5"><ShieldCheck className="h-3 w-3 text-sage" strokeWidth={2} /> AES-256-GCM</span>
          <span className="hidden md:inline">Argon2id t=3 m=64MiB</span>
          <button onClick={() => vaultDir && window.vault.reveal(vaultDir)} title={vaultDir}
            className="btn hidden max-w-[320px] truncate text-stone-500 hover:text-stone-300 lg:inline">
            {vaultDir}</button>
          <span className="ml-auto truncate text-fog">{status}</span>
        </footer>
      </div>

      {palOpen && (
        <Palette
          files={files} openIds={openIds} onClose={() => setPalOpen(false)}
          onOpen={(id) => { setPalOpen(false); doOpen(id) }}
          onImport={() => { setPalOpen(false); doImport() }}
          onImportFolder={() => { setPalOpen(false); doImportFolder() }}
          onLock={() => { setPalOpen(false); doLock() }}
          onPw={() => { setPalOpen(false); setPwModal(true) }}
          onLan={() => { setPalOpen(false); setLanOpen(true) }}
        />
      )}

      {importProg && (
        <div className="fixed inset-0 z-40 grid place-items-center bg-black/60 p-4">
          <div className="animate-pop w-[420px] max-w-full rounded-[10px] border border-line bg-panel p-5">
            <div className="flex items-center justify-between gap-3">
              <h3 className="truncate text-[14px] font-semibold text-stone-100">
                {importProg.phase === 'scan' ? 'Scanning folder…' : `${opVerb(importProg.op)}: ${importProg.root}`}
              </h3>
              <span className="shrink-0 font-mono text-[11px] text-brass">
                {progStats ? `%${Math.floor(progStats.frac * 100)}` : '…'}
              </span>
            </div>
            <div className="mt-3 h-2 overflow-hidden rounded-full bg-white/10">
              <div className="h-full rounded-full bg-brass transition-[width]" style={{ width: `${Math.floor((progStats?.frac ?? 0) * 100)}%` }} />
            </div>
            <div className="mt-3 min-h-[18px] truncate font-mono text-[11px] text-fog" title={importProg.current}>
              {importProg.phase === 'scan' ? 'counting files, speed and ETA in a second' : (importProg.current || 'finishing…')}
            </div>
            <div className="mt-2 grid grid-cols-2 gap-x-4 gap-y-1 font-mono text-[11px] text-stone-500">
              <span>files <span className="text-stone-300">{importProg.done}/{importProg.total || '…'}</span></span>
              <span>size <span className="text-stone-300">{fmtSize(importProg.bytesDone)}/{importProg.bytesTotal ? fmtSize(importProg.bytesTotal) : '…'}</span></span>
              <span>speed <span className="text-stone-300">{progStats ? `${fmtSize(progStats.speed)}/s` : '…'}</span></span>
              <span>left <span className="text-stone-300">{progStats ? fmtDur(progStats.eta) : '…'}</span> · elapsed {progStats ? fmtDur(progStats.elapsed) : '…'}</span>
            </div>
            <button disabled={cancelling} onClick={doCancelImport}
              className="btn mt-4 w-full rounded-lg border border-line px-4 py-2 text-[13px] text-stone-300 hover:border-stone-500 disabled:opacity-50">
              {cancelling ? 'Cancelling…' : 'Cancel (keeps what is done)'}</button>
          </div>
        </div>
      )}

      <div className="fixed bottom-10 right-4 z-50 flex flex-col gap-2">
        {toasts.map((t) => (
          <div key={t.id} className="animate-toast flex items-center gap-2 rounded-lg border border-line bg-panel2 px-3.5 py-2 text-[13px] shadow-xl">
            <Check className="h-3.5 w-3.5 text-sage" strokeWidth={2} />{t.msg}</div>
        ))}
      </div>

      {folderDelTarget && (
        <Modal title="Delete folder?" onClose={() => { if (!deletingFolder) setFolderDelTarget(null) }}>
          <p className="break-all font-mono text-[12px] text-fog">{folderDelTarget}/…</p>
          <p className="mt-1 text-[13px] text-fog">Every entry under this prefix goes with its encrypted blocks. No way back.</p>
          <div className="mt-4 flex gap-2">
            <button disabled={deletingFolder} onClick={doDeleteFolder} className="btn flex-1 rounded-lg bg-rust px-4 py-2 text-[13px] font-semibold text-white hover:brightness-110 disabled:opacity-50">{deletingFolder ? 'Deleting…' : 'Delete'}</button>
            <button disabled={deletingFolder} onClick={() => setFolderDelTarget(null)} className="btn flex-1 rounded-lg border border-line px-4 py-2 text-[13px] disabled:opacity-50">Cancel</button>
          </div>
        </Modal>
      )}
      {delTarget && (
        <Modal title="Delete entry?" onClose={() => { if (!deleting) setDelTarget(null) }}>
          <p className="break-all font-mono text-[12px] text-fog">{delTarget.name}</p>
          <p className="mt-1 text-[13px] text-fog">The encrypted block is overwritten on disk. No way back.</p>
          <div className="mt-4 flex gap-2">
            <button disabled={deleting} onClick={doDelete} className="btn flex-1 rounded-lg bg-rust px-4 py-2 text-[13px] font-semibold text-white hover:brightness-110 disabled:opacity-50">{deleting ? 'Deleting…' : 'Delete'}</button>
            <button disabled={deleting} onClick={() => setDelTarget(null)} className="btn flex-1 rounded-lg border border-line px-4 py-2 text-[13px] disabled:opacity-50">Cancel</button>
          </div>
        </Modal>
      )}
      {importReport && (
        <Modal title="Folder import report" onClose={() => setImportReport(null)} wide>
          <p className="text-[13px] text-fog">
            <span className="font-semibold text-stone-100">{importReport.imported}</span> files encrypted
            {importReport.skipped.length > 0 && (
              <>, <span className="font-semibold text-brass">{importReport.skipped.length} skipped</span></>)}
            {importReport.emptyDirs.length > 0 && (
              <>, <span className="text-stone-300">{importReport.emptyDirs.length} empty folders</span> (nothing to store)</>)}
            .
          </p>
          {importReport.skipped.length > 0 && (
            <div className="mt-3 max-h-[220px] overflow-y-auto rounded-lg border border-line bg-ink p-2">
              {importReport.skipped.map((s, i) => (
                <div key={i} className="border-b border-line/50 px-1.5 py-1.5 last:border-0">
                  <p className="break-all font-mono text-[11px] text-stone-300">{s.path}</p>
                  <p className="mt-0.5 text-[11px] text-brass">{s.reason}</p>
                </div>
              ))}
              {importReport.skippedExtra > 0 && (
                <p className="px-1.5 py-1 font-mono text-[11px] text-stone-500">+{importReport.skippedExtra} more skipped</p>
              )}
            </div>
          )}
          {importReport.emptyDirs.length > 0 && (
            <p className="mt-2 break-all font-mono text-[11px] text-stone-500">
              Empty: {importReport.emptyDirs.slice(0, 10).join(', ')}{importReport.emptyDirs.length > 10 ? '…' : ''}{importReport.emptyExtra > 0 ? ` (+${importReport.emptyExtra} more)` : ''}</p>
          )}
          <div className="mt-4">
            <button onClick={() => setImportReport(null)} className="btn w-full rounded-lg bg-brass px-4 py-2 text-[13px] font-semibold text-[#1a1408] hover:bg-[#f0b45a]">Done</button>
          </div>
        </Modal>
      )}
      {pendingImport && (
        <Modal title={`Encrypt ${pendingImport.total} files?`} onClose={() => { if (!confirming) setPendingImport(null) }} wide>
          <p className="break-all font-mono text-[12px] text-fog">{pendingImport.root}/…</p>
          <p className="mt-1.5 text-[13px] text-fog">
            <span className="font-semibold text-stone-100">{pendingImport.total} files</span>
            {' · '}{fmtSize(pendingImport.bytesTotal)} total.
            {pendingImport.skipped.length > 0 && (
              <> <span className="text-brass">{pendingImport.skipped.length + pendingImport.skippedExtra} won't come</span> (unreadable or too large).</>)}
            {pendingImport.emptyDirs.length > 0 && (
              <> {pendingImport.emptyDirs.length + pendingImport.emptyExtra} empty folders hold nothing to store.</>)}
          </p>
          <p className="mt-1 text-[12px] text-stone-500">Takes a while — progress shows live and Cancel keeps finished files.</p>
          <div className="mt-4 flex gap-2">
            <button disabled={confirming} onClick={runImportConfirm} className="btn flex-1 rounded-lg bg-brass px-4 py-2 text-[13px] font-semibold text-[#1a1408] hover:bg-[#f0b45a] disabled:opacity-50">
              {confirming ? 'Starting…' : `Encrypt ${pendingImport.total} files`}</button>
            <button disabled={confirming} onClick={() => setPendingImport(null)} className="btn flex-1 rounded-lg border border-line px-4 py-2 text-[13px] disabled:opacity-50">Not now</button>
          </div>
        </Modal>
      )}

      {renTarget && (
        <Modal title="Rename" onClose={() => setRenTarget(null)}>
          <input value={renName} onChange={(e) => setRenName(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Enter') doRename() }} autoFocus spellCheck={false}
            className="no-ring mt-1 w-full rounded-lg border border-line bg-ink px-3 py-2 text-[13px] focus:border-brassdim" />
          <div className="mt-4 flex gap-2">
            <button onClick={doRename} className="btn flex-1 rounded-lg bg-brass px-4 py-2 text-[13px] font-semibold text-[#1a1408] hover:bg-[#f0b45a]">Save</button>
            <button onClick={() => setRenTarget(null)} className="btn flex-1 rounded-lg border border-line px-4 py-2 text-[13px]">Cancel</button>
          </div>
        </Modal>
      )}

      {pwModal && (
        <Modal title="Change master password" onClose={() => { setPwModal(false); setNewPw(''); setNewPw2('') }}>
          <p className="text-[13px] text-fog">Every entry gets resealed with the new key. Takes a moment.</p>
          <input type="password" value={newPw} onChange={(e) => setNewPw(e.target.value)} placeholder="New password"
            className="no-ring mt-3 w-full rounded-lg border border-line bg-ink px-3 py-2 text-[13px] focus:border-brassdim" />
          <input type="password" value={newPw2} onChange={(e) => setNewPw2(e.target.value)} placeholder="Repeat"
            onKeyDown={(e) => { if (e.key === 'Enter') doChangePw() }}
            className="no-ring mt-2 w-full rounded-lg border border-line bg-ink px-3 py-2 text-[13px] focus:border-brassdim" />
          <div className="mt-4 flex gap-2">
            <button disabled={busy} onClick={doChangePw} className="btn flex-1 rounded-lg bg-brass px-4 py-2 text-[13px] font-semibold text-[#1a1408] hover:bg-[#f0b45a] disabled:opacity-50">Change</button>
            <button onClick={() => { setPwModal(false); setNewPw(''); setNewPw2('') }} className="btn flex-1 rounded-lg border border-line px-4 py-2 text-[13px]">Cancel</button>
          </div>
        </Modal>
      )}

      {previewFile && (
        <PreviewModal file={previewFile} onClose={() => setPreviewFile(null)} onOpenExternal={(id) => { setPreviewFile(null); doOpen(id) }} />
      )}
      {lanOpen && <LanModal vaultDir={vaultDir} onClose={() => setLanOpen(false)} />}
    </div>
  )
}

/* ------------------------------ small pieces ------------------------------ */

function IconBtn({ children, title, onClick, danger }: { children: React.ReactNode; title: string; onClick: () => void; danger?: boolean }) {
  return (
    <button title={title} onClick={(e) => { e.stopPropagation(); onClick() }}
      className={`btn rounded-md p-1.5 ${danger ? 'text-stone-500 hover:bg-rust/20 hover:text-rust' : 'text-stone-500 hover:bg-white/10 hover:text-stone-200'}`}>
      {children}</button>
  )
}

function Modal({ title, children, onClose, wide }: { title: string; children: React.ReactNode; onClose: () => void; wide?: boolean }) {
  // Swallow the second half of an accidental double-click: the backdrop
  // ignores clicks for a moment after opening so it can't instantly close.
  const born = useRef(Date.now())
  return (
    <div className="fixed inset-0 z-40 grid place-items-center bg-black/60 p-4"
      onClick={() => { if (Date.now() - born.current > 300) onClose() }}>
      <div className={`animate-pop max-w-full rounded-[10px] border border-line bg-panel p-5 ${wide ? 'w-[480px]' : 'w-[380px]'}`} onClick={(e) => e.stopPropagation()}>
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

function Palette({ files, openIds, onClose, onOpen, onImport, onImportFolder, onLock, onPw, onLan }: {
  files: FileEntry[]; openIds: Set<string>; onClose: () => void
  onOpen: (id: string) => void; onImport: () => void; onImportFolder: () => void; onLock: () => void; onPw: () => void; onLan: () => void
}) {
  const [q, setQ] = useState('')
  const [sel, setSel] = useState(0)
  const inputRef = useRef<HTMLInputElement>(null)
  const born = useRef(Date.now())
  useEffect(() => { inputRef.current?.focus() }, [])

  const fz = q.toLowerCase()
  const matched = files.filter((f) => f.name.toLowerCase().includes(fz)).slice(0, 6)
  const actions = [
    { label: 'Add files', hint: 'encrypt', run: onImport },
    { label: 'Add folder', hint: 'encrypt the tree', run: onImportFolder },
    { label: 'Phone access', hint: 'serve on LAN', run: onLan },
    { label: 'Change master password', hint: 'reseal the vault', run: onPw },
    { label: 'Lock vault', hint: 'wipe key from memory', run: onLock },
  ].filter((a) => a.label.toLocaleLowerCase('en').includes(fz))
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
    <div className="fixed inset-0 z-40 bg-black/60 p-4 pt-[14vh]"
      onClick={() => { if (Date.now() - born.current > 300) onClose() }}>
      <div className="animate-pop mx-auto w-[560px] max-w-full overflow-hidden rounded-[10px] border border-line bg-panel shadow-2xl" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center gap-2 border-b border-line px-3.5 transition-colors focus-within:border-brassdim">
          <Command className="h-4 w-4 shrink-0 text-fog" strokeWidth={1.75} />
          <input ref={inputRef} value={q} onChange={(e) => setQ(e.target.value)} placeholder="Files, actions…"
            spellCheck={false} className="no-ring w-full bg-transparent py-2.5 text-[13px] placeholder:text-stone-600" />
          <kbd className="rounded border border-line px-1.5 font-mono text-[10px] text-stone-500">esc</kbd>
        </div>
        <div className="max-h-[320px] overflow-y-auto p-1.5">
          {matched.length > 0 && <div className="px-2 pb-1 pt-1.5 text-[11px] font-medium uppercase tracking-wider text-stone-500">Files</div>}
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
          {actions.length > 0 && <div className="px-2 pb-1 pt-2 text-[11px] font-medium uppercase tracking-wider text-stone-500">Actions</div>}
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
          {total === 0 && <div className="px-3 py-6 text-center text-[13px] text-stone-500">No matches.</div>}
        </div>
        <div className="flex items-center gap-3 border-t border-line px-3.5 py-2 font-mono text-[10px] text-stone-500">
          <span>↑↓ navigate</span><span>↵ run</span><span className="ml-auto">{total} results</span>
        </div>
      </div>
    </div>
  )
}

