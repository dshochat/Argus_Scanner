import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// outDir is relative to this config's root (the frontend dir), so the build
// lands in dashboard/server/static where FastAPI serves it. In dev, /api
// proxies to the locally running `argus dashboard serve`.
export default defineConfig({
  plugins: [react()],
  base: "/",
  build: {
    outDir: "../server/static",
    emptyOutDir: true,
    sourcemap: false,
  },
  server: {
    port: 5173,
    proxy: {
      "/api": "http://127.0.0.1:8000",
    },
  },
});
