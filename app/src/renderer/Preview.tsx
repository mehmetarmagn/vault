import { useEffect, useRef, useState } from 'react'
import * as XLSX from 'xlsx'
import {
  ExternalLink, FileWarning, Loader2, Maximize2, Minus, Plus, RotateCcw, Volume2, X,
} from 'lucide-react'

export type PreviewFile = {
  id: string
  name: string
  size: number
  mime: string
}

type Kind = 'video' | 'audio' | 'image' | 'pdf' | 'sheet' | 'text' | 'other'

function extOf(name: string) {
  return (name.split('.').pop() ?? '').toLowerCase()
}

function kindOf(f: PreviewFile): Kind {
  const m = f.mime || ''
  const e = extOf(f.name)
  if (m.startsWith('video/') || ['mp4', 'webm', 'mkv', 'mov', 'avi', 'ogv'].includes(e)) return 'video'
  if (m.startsWith('audio/') || ['mp3', 'wav', 'flac', 'ogg', 'oga', 'm4a', 'opus'].includes(e)) return 'audio'
  if (m.startsWith('image/') || ['png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp', 'svg'].includes(e)) return 'image'
  if (m === 'application/pdf' || e === 'pdf') return 'pdf'
  if (['xlsx', 'xls', 'csv'].includes(e)) return 'sheet'
  if (m.startsWith('text/') || ['txt', 'md', 'json', 'js', 'ts', 'tsx', 'html', 'css', 'log', 'xml', 'yml', 'yaml', 'toml', 'py', 'go', 'rs'].includes(e)) return 'text'
  return 'other'
}

export function canPreview(f: PreviewFile) {
  return kindOf(f) !== 'other'
}

function b64ToBytes(b64: string) {
  const bin = atob(b64)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

export default function PreviewModal({ file, onClose, onOpenExternal }: {
  file: PreviewFile
  onClose: () => void
  onOpenExternal: (id: string) => void
}) {
  const kind = kindOf(file)
  const [streamUrl, setStreamUrl] = useState<string | null>(null)
  const [streamToken, setStreamToken] = useState<string | null>(null)
  const [err, setErr] = useState('')
  const [loading, setLoading] = useState(kind !== 'other')

  useEffect(() => {
    let dead = false
    setErr('')
    if (kind === 'other') { setLoading(false); return }
    if (kind === 'text' || kind === 'sheet') { setLoading(false); return } // read() path loads itself
    window.vault.stream(file.id).then((r) => {
      if (dead) { if (r.ok) window.vault.streamClose((r.data as any).token); return }
      if (r.ok) {
        setStreamUrl((r.data as any).url)
        setStreamToken((r.data as any).token)
      } else {
        setErr('Preview failed: ' + (r.error ?? 'unknown'))
        setLoading(false)
      }
    })
    return () => {
      dead = true
      if (streamToken) window.vault.streamClose(streamToken)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [file.id])

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  const born = useRef(Date.now())

  return (
    <div className="fixed inset-0 z-50 flex flex-col bg-black/85 p-3 sm:p-6"
      onClick={() => { if (Date.now() - born.current > 300) onClose() }}>
      <div className="mx-auto flex max-h-full w-full max-w-5xl flex-col overflow-hidden rounded-xl border border-line bg-panel"
        onClick={(e) => e.stopPropagation()}>
        <div className="flex shrink-0 items-center gap-2 border-b border-line px-4 py-2.5">
          <span className="min-w-0 flex-1 truncate text-[13px] font-medium text-stone-100" title={file.name}>{file.name}</span>
          <button onClick={() => onOpenExternal(file.id)} title="Open in external app"
            className="btn flex items-center gap-1 rounded-lg border border-line px-2.5 py-1.5 text-[12px] text-fog hover:text-stone-200">
            <ExternalLink className="h-3.5 w-3.5" strokeWidth={1.75} /> External</button>
          <button onClick={onClose} title="Close (Esc)"
            className="btn rounded-lg border border-line p-1.5 text-fog hover:text-stone-200">
            <X className="h-4 w-4" strokeWidth={1.75} /></button>
        </div>
        <div className="min-h-0 flex-1 overflow-auto p-3 sm:p-4">
          {err ? (
            <div className="flex items-center gap-2 text-[13px] text-rust"><FileWarning className="h-4 w-4" />{err}</div>
          ) : kind === 'video' || kind === 'audio' ? (
            <MediaPlayer url={streamUrl} kind={kind} onReady={() => setLoading(false)} />
          ) : kind === 'image' ? (
            <ImageViewer url={streamUrl} onReady={() => setLoading(false)} />
          ) : kind === 'pdf' ? (
            streamUrl
              ? <iframe src={streamUrl} title={file.name} className="h-[75vh] w-full rounded-lg bg-white"
                  onLoad={() => setLoading(false)} />
              : <Loading label="Decrypting document…" />
          ) : kind === 'sheet' ? (
            <SheetViewer file={file} />
          ) : kind === 'text' ? (
            <TextViewer file={file} />
          ) : (
            <div className="text-[13px] text-fog">No in-app preview for this type. Use External.</div>
          )}
          {loading && (kind === 'video' || kind === 'audio' || kind === 'image') && !streamUrl && (
            <Loading label="Decrypting…" />
          )}
        </div>
      </div>
    </div>
  )
}

function Loading({ label }: { label: string }) {
  return (
    <div className="flex items-center gap-2 py-10 text-[13px] text-fog">
      <Loader2 className="h-4 w-4 animate-spin" />{label}</div>
  )
}

/* ------------------------- video / audio +1000% ------------------------- */

function MediaPlayer({ url, kind, onReady }: { url: string | null; kind: 'video' | 'audio'; onReady: () => void }) {
  const elRef = useRef<HTMLVideoElement | HTMLAudioElement | null>(null)
  const graph = useRef<{ ctx: AudioContext; gain: GainNode } | null>(null)
  const [boost, setBoost] = useState(100) // percent, 100 = normal, max 1000

  function ensureGraph() {
    const el = elRef.current
    if (!el) return
    try {
      if (!graph.current) {
        const AC = window.AudioContext || (window as any).webkitAudioContext
        if (!AC) return
        const ctx: AudioContext = new AC()
        const src = ctx.createMediaElementSource(el as HTMLMediaElement)
        const gain = ctx.createGain()
        gain.gain.value = boost / 100
        src.connect(gain)
        gain.connect(ctx.destination)
        graph.current = { ctx, gain }
      }
      if (graph.current.ctx.state === 'suspended') void graph.current.ctx.resume()
    } catch { /* already wired */ }
  }

  useEffect(() => {
    if (graph.current) {
      const g = boost / 100
      graph.current.gain.gain.setTargetAtTime(g, graph.current.ctx.currentTime, 0.02)
    }
  }, [boost])

  useEffect(() => () => { try { graph.current?.ctx.close() } catch {} }, [])

  if (!url) return <Loading label="Decrypting media…" />
  const common = {
    ref: (n: any) => { elRef.current = n },
    src: url,
    controls: true,
    autoPlay: kind === 'video',
    onPlay: () => { ensureGraph(); onReady() },
    onLoadedData: () => onReady(),
    className: kind === 'video' ? 'max-h-[62vh] w-full rounded-lg bg-black' : 'w-full',
  }
  return (
    <div>
      {kind === 'video'
        ? <video {...common} playsInline />
        : <audio {...common} />}
      <div className="mt-3 rounded-lg border border-line bg-ink px-3 py-2.5">
        <div className="flex items-center gap-2 text-[12px] text-fog">
          <Volume2 className="h-4 w-4 shrink-0" strokeWidth={1.75} />
          <input type="range" min={0} max={1000} step={5} value={boost}
            onInput={ensureGraph}
            onChange={(e) => setBoost(Number(e.target.value))}
            className="w-full accent-[#e8a33d]" />
          <span className="w-14 shrink-0 text-right font-mono text-[12px] text-stone-200">{boost}%</span>
        </div>
        <p className="mt-1 text-[11px] text-stone-500">
          {boost > 100 ? 'Software boost active — distortion may appear near 1000%.' : 'Drag past 100% for software boost, up to 1000%.'}
        </p>
      </div>
    </div>
  )
}

/* ------------------------------ image zoom/pan ------------------------------ */

function ImageViewer({ url, onReady }: { url: string | null; onReady: () => void }) {
  const [scale, setScale] = useState(1)
  const [pos, setPos] = useState({ x: 0, y: 0 })
  const drag = useRef<{ x: number; y: number; px: number; py: number } | null>(null)

  if (!url) return <Loading label="Decrypting image…" />
  return (
    <div>
      <div className="mb-2 flex items-center gap-1.5 text-[12px] text-fog">
        <button onClick={() => setScale((s) => Math.min(8, +(s * 1.25).toFixed(2)))} className="btn rounded-md border border-line p-1.5 hover:text-stone-200"><Plus className="h-3.5 w-3.5" /></button>
        <button onClick={() => setScale((s) => Math.max(0.2, +(s / 1.25).toFixed(2)))} className="btn rounded-md border border-line p-1.5 hover:text-stone-200"><Minus className="h-3.5 w-3.5" /></button>
        <button onClick={() => { setScale(1); setPos({ x: 0, y: 0 }) }} className="btn rounded-md border border-line p-1.5 hover:text-stone-200"><RotateCcw className="h-3.5 w-3.5" /></button>
        <button onClick={() => setScale((s) => (s === 1 ? 2.5 : 1))} className="btn rounded-md border border-line p-1.5 hover:text-stone-200"><Maximize2 className="h-3.5 w-3.5" /></button>
        <span className="ml-1 font-mono">{Math.round(scale * 100)}%</span>
        <span className="ml-2 hidden sm:inline">scroll to zoom · drag to pan · double-click to reset</span>
      </div>
      <div className="grid max-h-[68vh] place-items-center overflow-hidden rounded-lg bg-ink"
        onWheel={(e) => setScale((s) => Math.max(0.2, Math.min(8, +(s * (e.deltaY < 0 ? 1.12 : 0.89)).toFixed(3))))}
        onMouseDown={(e) => { drag.current = { x: e.clientX, y: e.clientY, px: pos.x, py: pos.y } }}
        onMouseMove={(e) => { if (drag.current) setPos({ x: drag.current.px + e.clientX - drag.current.x, y: drag.current.py + e.clientY - drag.current.y }) }}
        onMouseUp={() => { drag.current = null }}
        onMouseLeave={() => { drag.current = null }}
        onDoubleClick={() => { setScale(1); setPos({ x: 0, y: 0 }) }}>
        <img src={url} alt="" draggable={false}
          onLoad={onReady}
          style={{ transform: `translate(${pos.x}px, ${pos.y}px) scale(${scale})`, cursor: scale > 1 ? 'grab' : 'default', maxHeight: '68vh' }}
          className="select-none" />
      </div>
    </div>
  )
}

/* --------------------------------- sheets --------------------------------- */

function SheetViewer({ file }: { file: PreviewFile }) {
  const [names, setNames] = useState<string[]>([])
  const [sel, setSel] = useState(0)
  const [rows, setRows] = useState<any[][]>([])
  const [err, setErr] = useState('')
  const wb = useRef<XLSX.WorkBook | null>(null)

  useEffect(() => {
    let dead = false
    window.vault.read(file.id).then((r) => {
      if (dead) return
      if (!r.ok) { setErr('Could not decrypt: ' + (r.error ?? '')); return }
      try {
        const bytes = b64ToBytes((r.data as any).b64)
        const isCsv = extOf(file.name) === 'csv'
        wb.current = isCsv
          ? XLSX.read(new TextDecoder().decode(bytes), { type: 'string' })
          : XLSX.read(bytes, { type: 'array' })
        const ns = wb.current.SheetNames
        setNames(ns)
        setSel(0)
        loadSheet(ns[0])
      } catch (e: any) {
        setErr('Could not parse spreadsheet: ' + (e?.message ?? e))
      }
    })
    function loadSheet(n: string) {
      const ws = wb.current!.Sheets[n]
      const json: any[][] = XLSX.utils.sheet_to_json(ws, { header: 1, raw: true, defval: '' })
      setRows(json.slice(0, 500))
    }
    return () => { dead = true }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [file.id])

  function pick(i: number) {
    setSel(i)
    const ws = wb.current!.Sheets[names[i]]
    const json: any[][] = XLSX.utils.sheet_to_json(ws, { header: 1, raw: true, defval: '' })
    setRows(json.slice(0, 500))
  }

  if (err) return <div className="text-[13px] text-rust">{err}</div>
  if (names.length === 0) return <Loading label="Decrypting spreadsheet…" />
  const cols = Math.max(0, ...rows.map((r) => r.length))
  return (
    <div>
      {names.length > 1 && (
        <div className="mb-2 flex gap-1.5 overflow-x-auto pb-1">
          {names.map((n, i) => (
            <button key={n} onClick={() => pick(i)}
              className={`shrink-0 rounded-lg border px-2.5 py-1 text-[12px] ${i === sel ? 'border-brassdim bg-panel2 text-stone-100' : 'border-line text-fog'}`}>{n}</button>
          ))}
        </div>
      )}
      <div className="max-h-[62vh] overflow-auto rounded-lg border border-line">
        <table className="border-collapse font-mono text-[11px]">
          <tbody>
            {rows.map((r, i) => (
              <tr key={i} className={i === 0 ? 'bg-panel2' : ''}>
                {Array.from({ length: Math.min(cols, 26) }).map((_, j) => (
                  <td key={j} className="max-w-[220px] overflow-hidden text-ellipsis whitespace-nowrap border border-line/60 px-2 py-1 text-stone-300">
                    {String(r[j] ?? '')}</td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="mt-1.5 font-mono text-[11px] text-stone-500">
        {names[sel]} · {rows.length}{rows.length >= 500 ? '+' : ''} rows shown · first row is the header</p>
    </div>
  )
}

/* ---------------------------------- text ---------------------------------- */

function TextViewer({ file }: { file: PreviewFile }) {
  const [text, setText] = useState<string | null>(null)
  const [err, setErr] = useState('')

  useEffect(() => {
    let dead = false
    window.vault.read(file.id).then((r) => {
      if (dead) return
      if (!r.ok) { setErr('Could not decrypt: ' + (r.error ?? '')); return }
      try {
        const t = new TextDecoder('utf-8', { fatal: false }).decode(b64ToBytes((r.data as any).b64))
        setText(t.slice(0, 1_000_000))
      } catch { setErr('Not readable as text.') }
    })
    return () => { dead = true }
  }, [file.id])

  if (err) return <div className="text-[13px] text-rust">{err}</div>
  if (text === null) return <Loading label="Decrypting text…" />
  return <pre className="max-h-[68vh] overflow-auto whitespace-pre-wrap rounded-lg bg-ink p-3 font-mono text-[12px] leading-relaxed text-stone-200">{text}</pre>
}
