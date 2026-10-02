export {}

declare global {
  interface Window {
    vault: {
      ping(): Promise<{ ok: boolean; data?: any; error?: string }>
      status(): Promise<{ ok: boolean; data?: any; error?: string }>
      defaultDir(): Promise<{ ok: boolean; data?: any; error?: string }>
      exists(vaultDir: string): Promise<{ ok: boolean; data?: any; error?: string }>
      selectDir(): Promise<{ ok: boolean; data?: any; error?: string }>
      reveal(vaultDir: string): Promise<{ ok: boolean; data?: any; error?: string }>
      init(vaultDir: string, password: string): Promise<{ ok: boolean; data?: any; error?: string }>
      unlock(vaultDir: string, password: string): Promise<{ ok: boolean; data?: any; error?: string }>
      list(): Promise<{ ok: boolean; data?: any; error?: string }>
      importFile(): Promise<{ ok: boolean; data?: any; error?: string }>
      importFolder(): Promise<{ ok: boolean; data?: any; error?: string }>
      cancelImport(): Promise<{ ok: boolean; data?: any; error?: string }>
      exportFolder(prefix: string): Promise<{ ok: boolean; data?: any; error?: string }>
      deleteFolder(prefix: string): Promise<{ ok: boolean; data?: any; error?: string }>
      open(fileId: string): Promise<{ ok: boolean; data?: any; error?: string }>
      reencrypt(fileId: string): Promise<{ ok: boolean; data?: any; error?: string }>
      closeFile(fileId: string): Promise<{ ok: boolean; data?: any; error?: string }>
      remove(fileId: string): Promise<{ ok: boolean; data?: any; error?: string }>
      rename(fileId: string, name: string): Promise<{ ok: boolean; data?: any; error?: string }>
      exportFile(fileId: string, suggestedName?: string): Promise<{ ok: boolean; data?: any; error?: string }>
      changePassword(newPassword: string): Promise<{ ok: boolean; data?: any; error?: string }>
      lock(): Promise<{ ok: boolean; data?: any; error?: string }>
      onEvent(cb: (data: any) => void): void
    }
  }
}
