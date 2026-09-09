import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
const config = {
  plugins: [react()],
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: [],
  },
  build: {
    chunkSizeWarningLimit: 3600,
    rollupOptions: {
      output: {
        manualChunks(id: string) {
          if (id.includes('@noir-lang')) return 'noir-runtime'
          if (id.includes('@stellar') || id.includes('@scure') || id.includes('@noble')) {
            return 'stellar'
          }
          if (id.includes('react') || id.includes('react-dom')) return 'react'
        },
      },
    },
  },
}

export default defineConfig(config)
