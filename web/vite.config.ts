import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// The build lands inside internal/web so that Go's //go:embed can pick it up
// without a copy step; `make web` runs this and then restores the .gitkeep that
// emptyOutDir removes.
//
// During development, run the Go binary and `npm run dev` side by side: the
// proxy below sends /api to the real backend, so the panel talks to a live
// resolver instead of fixtures.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  build: {
    outDir: "../internal/web/dist",
    emptyOutDir: true,
    // The panel is served from a Raspberry Pi over the LAN; a visible warning
    // when a chunk grows past this keeps first paint honest.
    chunkSizeWarningLimit: 500,
  },
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: process.env.AEGIS_API ?? "http://127.0.0.1:8080",
        changeOrigin: true,
      },
    },
  },
});
