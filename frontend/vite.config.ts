import { resolve } from "path";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  // strictPort: a second `npm run dev` must fail loudly. Silently moving to 5174 serves a copy the API's
  // CORS allow-list does not cover, so every request would be blocked.
  server: { port: 5173, strictPort: true },
  build: {
    rollupOptions: {
      input: {
        main: resolve(__dirname, "index.html"),
        platform: resolve(__dirname, "platform/index.html"),
      },
    },
  },
});
