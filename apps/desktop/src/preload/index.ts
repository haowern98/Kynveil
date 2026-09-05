import { contextBridge, ipcRenderer } from 'electron'

import { createKynveilApi } from './api.js'

contextBridge.exposeInMainWorld(
  'kynveil',
  createKynveilApi((channel) => ipcRenderer.invoke(channel))
)
