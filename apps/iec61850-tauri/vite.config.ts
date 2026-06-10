import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Configuración Vite recomendada para Tauri: puerto fijo y sin vigilar src-tauri.
export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    watch: {
      ignored: ["**/src-tauri/**"],
    },
  },
});
