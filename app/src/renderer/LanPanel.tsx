import { useEffect, useRef, useState } from 'react'
import { Loader2, Power, Smartphone, X } from 'lucide-react'

export default function LanModal({ vaultDir, onClose }: { vaultDir: string; onClose: () => void }) {
  const born = useRef(Date.now())
  const [port, setPort] = useState('6767')
  const [running, setRunning] = useState(false)
  const [activePort, setActivePort] = useState(6767)
  const [ips, setIps] = useState<string[]>([])
  const [sessions, setSessions] = useState(0)
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState('Same Wi-Fi only. Login uses your vault password.')

  async function refresh() {
    try {
      const s = await window.vault.lanStatus()
      if (s.ok) {
        setRunning(!!(s.data as any).running)
        if ((s.data as any).port) setActivePort((s.data as any).port)
        setSessions((s.data as any).sessions ?? 0)
      }
      const ipsR = await window.vault.lanIps()
      if (ipsR.ok) setIps((ipsR.data as any).ips ?? [])
    } catch { /* core unreachable */ }
  }

  useEffect(() => {
    refresh()
    const t = setInterval(refresh, 3000)
    return () => clearInterval(t)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  async function start() {
    setBusy(true)
    setMsg('Starting…')
    const p = Math.max(1, Math.min(65535, parseInt(port, 10) || 6767))
    const r = await window.vault.lanStart(vaultDir, p)
    setBusy(false)
    if (r.ok && (r.data as any).running) {
      setRunning(true)
      setActivePort((r.data as any).port ?? p)
      setMsg('Live. Open the address on your phone.')
    } else {
      setMsg('Could not start: ' + (r.error ?? 'unknown'))
    }
    await refresh()
  }

  async function stop() {
    setBusy(true)
    await window.vault.lanStop()
    setBusy(false)
    setRunning(false)
    setMsg('Stopped. Phone sessions are dead.')
    await refresh()
  }

  return (
    <div className="fixed inset-0 z-50 grid place-items-center bg-black/70 p-4"
      onClick={() => { if (Date.now() - born.current > 300) onClose() }}>
      <div className="w-[420px] max-w-full rounded-xl border border-line bg-panel p-5"
        onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center gap-2">
          <Smartphone className="h-4 w-4 text-brass" strokeWidth={1.75} />
          <h3 className="flex-1 text-[14px] font-semibold text-stone-100">Phone access (LAN)</h3>
          <button onClick={onClose} className="btn rounded-lg border border-line p-1.5 text-fog hover:text-stone-200">
            <X className="h-4 w-4" strokeWidth={1.75} /></button>
        </div>

        <div className="mt-3 flex items-center gap-2 rounded-lg border border-line bg-ink px-3 py-2">
          <span className={`h-2 w-2 rounded-full ${running ? 'bg-sage' : 'bg-stone-600'}`} />
          <span className="font-mono text-[12px] text-stone-300">
            {running ? `Serving on port ${activePort}` : 'Stopped'}</span>
          {running && sessions > 0 && (
            <span className="ml-auto font-mono text-[11px] text-fog">{sessions} session{sessions === 1 ? '' : 's'}</span>
          )}
        </div>

        {!running ? (
          <div className="mt-3 flex gap-2">
            <input value={port} onChange={(e) => setPort(e.target.value.replace(/[^0-9]/g, '').slice(0, 5))}
              placeholder="6767" inputMode="numeric" spellCheck={false}
              className="no-ring w-24 rounded-lg border border-line bg-ink px-3 py-2 font-mono text-[13px] focus:border-brassdim" />
            <button disabled={busy} onClick={start}
              className="btn flex flex-1 items-center justify-center gap-1.5 rounded-lg bg-brass px-4 py-2 text-[13px] font-semibold text-[#1a1408] hover:bg-[#f0b45a] disabled:opacity-50">
              {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Power className="h-4 w-4" strokeWidth={2} />} Start server</button>
          </div>
        ) : (
          <div className="mt-3 space-y-1.5">
            {ips.length === 0 && (
              <p className="font-mono text-[12px] text-fog">http://localhost:{activePort} (no LAN address found)</p>
            )}
            {ips.map((ip) => (
              <p key={ip} className="select-all rounded-lg border border-line bg-ink px-3 py-2 font-mono text-[13px] text-brass">
                http://{ip}:{activePort}</p>
            ))}
            <button disabled={busy} onClick={stop}
              className="btn mt-1 w-full rounded-lg border border-line px-4 py-2 text-[13px] text-stone-300 hover:border-stone-500 disabled:opacity-50">
              Stop server</button>
          </div>
        )}

        <p className="mt-3 text-[12px] leading-relaxed text-fog">{msg}</p>
        <ul className="mt-1 list-disc space-y-0.5 pl-4 text-[12px] leading-relaxed text-stone-500">
          <li>Phone must be on the same Wi-Fi.</li>
          <li>Login uses the vault password; 5 wrong tries = 1 minute block.</li>
          <li>Traffic is plain HTTP on your local network — use only on networks you trust.</li>
          <li>Locking the vault kills every phone session.</li>
        </ul>
      </div>
    </div>
  )
}
