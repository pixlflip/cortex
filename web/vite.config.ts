import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  build: {
    outDir: process.env.CORTEX_WEB_OUT_DIR || '../src/cortex/web_dist',
    emptyOutDir: true,
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (!id.includes('/node_modules/')) return undefined
          if (id.includes('/lucide-react/')) return 'icons'
          if (id.includes('/react-markdown/') || id.includes('/remark-') || id.includes('/rehype-') || id.includes('/unified/') || id.includes('/micromark') || id.includes('/mdast-') || id.includes('/hast-')) return 'markdown'
          if (id.includes('/react-router')) return 'router'
          if (id.includes('/react-dom/')) return 'react-dom'
          if (id.includes('/react/')) return 'react'
          return 'vendor'
        },
      },
    },
  },
  server: {
    port: 5173,
    proxy: {
      '/api': 'http://127.0.0.1:8765',
      '/healthz': 'http://127.0.0.1:8765',
    },
  },
})
