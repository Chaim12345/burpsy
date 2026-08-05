import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  build: {
    outDir: '../../ui/dist-react',
    emptyOutDir: true,
    rollupOptions: {
      input: {
        app: './index.html',
      },
      output: {
        entryFileNames: 'app.js',
        assetFileNames: 'assets/[name].[ext]',
      },
    },
  },
});
