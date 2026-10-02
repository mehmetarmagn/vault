// Preload: renderer'a sadece güvenli vault API'sini açar.
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('vault', {
  ping: () => ipcRenderer.invoke('vault:ping'),
  status: () => ipcRenderer.invoke('vault:status'),
  init: (vaultDir, password) => ipcRenderer.invoke('vault:init', { vaultDir, password }),
  unlock: (vaultDir, password) => ipcRenderer.invoke('vault:unlock', { vaultDir, password }),
  list: () => ipcRenderer.invoke('vault:list'),
  importFile: () => ipcRenderer.invoke('vault:import'),
  open: (fileId) => ipcRenderer.invoke('vault:open', { fileId }),
  reencrypt: (fileId) => ipcRenderer.invoke('vault:reencrypt', { fileId }),
  closeFile: (fileId) => ipcRenderer.invoke('vault:close', { fileId }),
  remove: (fileId) => ipcRenderer.invoke('vault:delete', { fileId }),
  rename: (fileId, name) => ipcRenderer.invoke('vault:rename', { fileId, name }),
  exportFile: (fileId, suggestedName) => ipcRenderer.invoke('vault:export', { fileId, suggestedName }),
  changePassword: (newPassword) => ipcRenderer.invoke('vault:change-password', { newPassword }),
  lock: () => ipcRenderer.invoke('vault:lock'),
  onEvent: (cb) => ipcRenderer.on('vault:event', (_e, data) => cb(data)),
});
