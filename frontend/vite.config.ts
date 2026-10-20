/// <reference types="vitest/config" />
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    // The API runs on its own origin in development. Proxying it here keeps the
    // browser on a single origin, so no CORS preflight is needed locally.
    proxy: {
      '/api': {
        target: process.env.VITE_API_PROXY ?? 'http://localhost:5080',
        changeOrigin: true,
      },
    },
  },
  test: {
    // The crypto suite needs WebCrypto, which Node provides natively. No DOM
    // is involved, so there is no reason to pay for jsdom.
    environment: 'node',
    include: ['src/**/*.test.ts'],
  },
})
