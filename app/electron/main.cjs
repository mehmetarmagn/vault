// Electron main process (CommonJS). Pencere + Go sidecar yönetimi + event bridge.
const { app, BrowserWindow, ipcMain, dialog, shell } = require('electron');
const path = require('path');
const fs = require('fs');
const { spawn } = require('child_process');

const isDev = !app.isPackaged;

let win = null;
let goProc = null;
let reqId = 1;
const pending = new Map();
let goBuffer = '';

function goBinaryPath() {
  const candidates = [
    path.join(__dirname, '..', '..', 'vault-core', 'vault-core.exe'),
    path.join(process.resourcesPath || '', 'vault-core.exe'),
    path.join(path.dirname(process.execPath || ''), 'vault-core.exe'),
  ];
  for (const c of candidates) {
    try { if (c && fs.existsSync(c)) return c; } catch {}
  }
  return candidates[0];
}

function forwardEvent(msg) {
  try {
    if (win && !win.isDestroyed()) win.webContents.send('vault:event', msg.data);
  } catch {}
}

function ensureGo() {
  if (goProc && !goProc.killed) return goProc;
  const bin = goBinaryPath();
  goProc = spawn(bin, ['serve'], { stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
  goProc.stdout.setEncoding('utf-8');
  goProc.stdout.on('data', (chunk) => {
    goBuffer += chunk;
    let idx;
    while ((idx = goBuffer.indexOf('\n')) >= 0) {
      const line = goBuffer.slice(0, idx).trim();
      goBuffer = goBuffer.slice(idx + 1);
      if (!line) continue;
      try {
        const msg = JSON.parse(line);
        if (msg.id === 0) { forwardEvent(msg); continue; } // Go watcher event'i
        const cb = pending.get(msg.id);
        if (cb) { pending.delete(msg.id); cb(msg); }
      } catch {}
    }
  });
  goProc.stderr.on('data', () => {});
  goProc.on('exit', () => { goProc = null; });
  return goProc;
}

function callGo(obj) {
  return new Promise((resolve) => {
    const proc = ensureGo();
    const id = obj.id ?? reqId++;
    const payload = JSON.stringify({ ...obj, id }) + '\n';
    pending.set(id, resolve);
    proc.stdin.write(payload);
    setTimeout(() => {
      if (pending.has(id)) { pending.delete(id); resolve({ id, ok: false, error: 'go-timeout' }); }
    }, 90000);
  });
}

function createWindow() {
  win = new BrowserWindow({
    width: 1280,
    height: 840,
    minWidth: 960,
    minHeight: 620,
    backgroundColor: '#0b0f17',
    title: 'Secure Vault',
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, 'preload.cjs'),
      contextIsolation: true,
      sandbox: true,
      nodeIntegration: false,
    },
  });
  if (isDev) {
    win.loadURL('http://localhost:5173');
  } else {
    win.loadFile(path.join(__dirname, '..', 'dist', 'index.html'));
  }
}

app.whenReady().then(() => {
  ensureGo();
  ipcMain.handle('vault:ping', async () => callGo({ cmd: 'ping' }));
  ipcMain.handle('vault:status', async () => callGo({ cmd: 'status' }));
  ipcMain.handle('vault:init', async (_e, { vaultDir, password }) => callGo({ cmd: 'init', vaultDir, password }));
  ipcMain.handle('vault:unlock', async (_e, { vaultDir, password }) => callGo({ cmd: 'unlock', vaultDir, password }));
  ipcMain.handle('vault:list', async () => callGo({ cmd: 'list' }));
  ipcMain.handle('vault:import', async () => {
    const r = await dialog.showOpenDialog(win, { properties: ['openFile', 'multiSelections'] });
    if (r.canceled || !r.filePaths.length) return { ok: true, data: { skipped: true } };
    const results = [];
    for (const p of r.filePaths) results.push(await callGo({ cmd: 'import', path: p }));
    return { ok: true, data: results };
  });
  ipcMain.handle('vault:open', async (_e, { fileId }) => {
    const res = await callGo({ cmd: 'open', fileId });
    if (res.ok && res.data && res.data.tempPath) {
      await shell.openPath(res.data.tempPath);
    }
    return res;
  });
  ipcMain.handle('vault:reencrypt', async (_e, { fileId }) => callGo({ cmd: 'reencrypt', fileId }));
  ipcMain.handle('vault:close', async (_e, { fileId }) => callGo({ cmd: 'close', fileId }));
  ipcMain.handle('vault:delete', async (_e, { fileId }) => callGo({ cmd: 'delete', fileId }));
  ipcMain.handle('vault:rename', async (_e, { fileId, name }) => callGo({ cmd: 'rename', fileId, name }));
  ipcMain.handle('vault:export', async (_e, { fileId, suggestedName }) => {
    const r = await dialog.showSaveDialog(win, { defaultPath: suggestedName || 'dosya' });
    if (r.canceled || !r.filePath) return { ok: true, data: { skipped: true } };
    return callGo({ cmd: 'export', fileId, destPath: r.filePath });
  });
  ipcMain.handle('vault:change-password', async (_e, { newPassword }) => callGo({ cmd: 'change-password', newPassword }));
  ipcMain.handle('vault:lock', async () => callGo({ cmd: 'lock' }));

  createWindow();
  app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
});

app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });
app.on('before-quit', () => { try { if (goProc) goProc.kill(); } catch {} });
