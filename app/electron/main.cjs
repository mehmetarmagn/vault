// Electron main process (CommonJS). Window + Go sidecar management + event bridge.
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

// Automatic vault location: never ask the user for a folder.
// %APPDATA%/Secure Vault/vault (app.getPath('userData')/vault)
function defaultVaultDir() {
  try {
    return path.join(app.getPath('userData'), 'vault');
  } catch {
    return path.join(app.getPath('documents'), 'Secure Vault');
  }
}

function resolveVaultDir(input) {
  const d = (input || '').trim();
  if (d) return d;
  return defaultVaultDir();
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
        if (msg.id === 0) { forwardEvent(msg); continue; } // Go watcher event
        const cb = pending.get(msg.id);
        if (cb) { pending.delete(msg.id); cb(msg); }
      } catch {}
    }
  });
  goProc.stderr.on('data', () => {});
  goProc.on('exit', () => { goProc = null; });
  return goProc;
}

function callGo(obj, timeoutMs) {
  return new Promise((resolve) => {
    const proc = ensureGo();
    const id = obj.id ?? reqId++;
    const payload = JSON.stringify({ ...obj, id }) + '\n';
    pending.set(id, resolve);
    proc.stdin.write(payload);
    setTimeout(() => {
      if (pending.has(id)) { pending.delete(id); resolve({ id, ok: false, error: 'go-timeout' }); }
    }, timeoutMs ?? 90000);
  });
}

function createWindow() {
  let icon;
  for (const p of [path.join(__dirname, 'icon.ico'), path.join(__dirname, '..', '..', 'assets', 'icon.ico')]) {
    try { if (fs.existsSync(p)) { icon = p; break; } } catch {}
  }
  win = new BrowserWindow({
    width: 1280,
    height: 840,
    minWidth: 960,
    minHeight: 620,
    backgroundColor: '#14120f',
    title: 'Secure Vault',
    icon,
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
  ipcMain.handle('vault:default-dir', async () => ({ ok: true, data: { path: defaultVaultDir() } }));
  ipcMain.handle('vault:exists', async (_e, { vaultDir }) => callGo({ cmd: 'exists', vaultDir: resolveVaultDir(vaultDir) }));
  ipcMain.handle('vault:select-dir', async () => {
    const r = await dialog.showOpenDialog(win, { properties: ['openDirectory', 'createDirectory'] });
    if (r.canceled || !r.filePaths.length) return { ok: true, data: { skipped: true } };
    return { ok: true, data: { path: r.filePaths[0] } };
  });
  ipcMain.handle('vault:reveal', async (_e, { vaultDir }) => {
    const dir = resolveVaultDir(vaultDir);
    try { await fs.promises.mkdir(dir, { recursive: true }); } catch {}
    shell.showItemInFolder(dir);
    return { ok: true };
  });
  ipcMain.handle('vault:init', async (_e, { vaultDir, password }) => callGo({ cmd: 'init', vaultDir: resolveVaultDir(vaultDir), password }));
  ipcMain.handle('vault:unlock', async (_e, { vaultDir, password }) => callGo({ cmd: 'unlock', vaultDir: resolveVaultDir(vaultDir), password }));
  ipcMain.handle('vault:list', async () => callGo({ cmd: 'list' }));
  ipcMain.handle('vault:import', async () => {
    const r = await dialog.showOpenDialog(win, { properties: ['openFile', 'multiSelections'] });
    if (r.canceled || !r.filePaths.length) return { ok: true, data: { skipped: true } };
    const results = [];
    for (const p of r.filePaths) results.push(await callGo({ cmd: 'import', path: p }, 1800000));
    return { ok: true, data: results };
  });
  ipcMain.handle('vault:import-folder', async () => {
    const r = await dialog.showOpenDialog(win, { properties: ['openDirectory'] });
    if (r.canceled || !r.filePaths.length) return { ok: true, data: { skipped: true } };
    return callGo({ cmd: 'import-folder', path: r.filePaths[0] }, 1800000);
  });
  ipcMain.handle('vault:cancel-import', async () => callGo({ cmd: 'cancel-import' }));
  ipcMain.handle('vault:export-folder', async (_e, { prefix }) => {
    const r = await dialog.showOpenDialog(win, { properties: ['openDirectory', 'createDirectory'] });
    if (r.canceled || !r.filePaths.length) return { ok: true, data: { skipped: true } };
    return callGo({ cmd: 'export-folder', prefix, destPath: r.filePaths[0] }, 1800000);
  });
  ipcMain.handle('vault:delete-folder', async (_e, { prefix }) => callGo({ cmd: 'delete-folder', prefix }, 1800000));
  ipcMain.handle('vault:open', async (_e, { fileId }) => {
    const res = await callGo({ cmd: 'open', fileId });
    if (res.ok && res.data && res.data.tempPath) {
      await shell.openPath(res.data.tempPath);
    }
    return res;
  });
  ipcMain.handle('vault:reencrypt', async (_e, { fileId }) => callGo({ cmd: 'reencrypt', fileId }, 600000));
  ipcMain.handle('vault:close', async (_e, { fileId }) => callGo({ cmd: 'close', fileId }));
  ipcMain.handle('vault:delete', async (_e, { fileId }) => callGo({ cmd: 'delete', fileId }, 600000));
  ipcMain.handle('vault:rename', async (_e, { fileId, name }) => callGo({ cmd: 'rename', fileId, name }));
  ipcMain.handle('vault:export', async (_e, { fileId, suggestedName }) => {
    const r = await dialog.showSaveDialog(win, { defaultPath: suggestedName || 'file' });
    if (r.canceled || !r.filePath) return { ok: true, data: { skipped: true } };
    return callGo({ cmd: 'export', fileId, destPath: r.filePath }, 600000);
  });
  ipcMain.handle('vault:change-password', async (_e, { newPassword }) => callGo({ cmd: 'change-password', newPassword }, 1800000));
  ipcMain.handle('vault:lock', async () => callGo({ cmd: 'lock' }));

  createWindow();
  app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
});

app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });
app.on('before-quit', () => { try { if (goProc) goProc.kill(); } catch {} });
