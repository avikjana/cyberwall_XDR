import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    proxy: {
      '/api': {
        target: 'http://localhost:5000',
        changeOrigin: true,
        secure: false
      },
      '/socket.io': {
        target: 'http://localhost:5000',
        changeOrigin: true,
        ws: true
      }
    }
  },
  optimizeDeps: {
    exclude: ['react-leaflet', 'leaflet']
  },
  build: {
    // Disable sourcemaps in production for smaller bundle size
    sourcemap: false,
    // Code-split large libraries into separate chunks for faster initial load
    rollupOptions: {
      output: {
        manualChunks: {
          'vendor-react': ['react', 'react-dom', 'react-router-dom'],
          'vendor-charts': ['recharts'],
          'vendor-animation': ['framer-motion'],
          'vendor-io': ['socket.io-client', 'axios']
        }
      }
    }
  }
});
