import { readFileSync } from "fs";
import { resolve } from "path";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  // strictPort: a second `npm run dev` must fail loudly. Silently moving to 5174 serves a copy the API's
  // CORS allow-list does not cover, so every request would be blocked.
  //
  // `./run.sh https` sets CERBERUS_TLS_KEY / CERBERUS_TLS_CERT so the dashboard is served over https://localhost.
  server: {
    port: 5173,
    strictPort: true,
    https:
      process.env.CERBERUS_TLS_KEY && process.env.CERBERUS_TLS_CERT
        ? { key: readFileSync(process.env.CERBERUS_TLS_KEY), cert: readFileSync(process.env.CERBERUS_TLS_CERT) }
        : undefined,
  },
  build: {
    rollupOptions: {
      input: {
        main: resolve(__dirname, "index.html"),
        platform: resolve(__dirname, "platform/index.html"),
      },
    },
  },
});
