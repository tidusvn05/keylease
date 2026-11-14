/// <reference types="vitest/config" />
import { fileURLToPath, URL } from "node:url";
import tailwindcss from "@tailwindcss/vite";
import { tanstackRouter } from "@tanstack/router-plugin/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// The console is a static SPA served by keylease-server. During development,
// API calls go to a local server (KEYLEASE_SERVER_URL, default 127.0.0.1:8080).
const apiTarget = process.env.KEYLEASE_SERVER_URL ?? "http://127.0.0.1:8080";

export default defineConfig({
  // Served by keylease-server at /console/ (or /api/console/ behind a proxy).
  base: "./",
  plugins: [
    // Must run before the React plugin.
    tanstackRouter({ target: "react", autoCodeSplitting: true }),
    react(),
    tailwindcss(),
  ],
  resolve: {
    alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) },
  },
  server: {
    proxy: {
      "/v1": apiTarget,
      "/healthz": apiTarget,
      "/readyz": apiTarget,
    },
  },
  build: {
    // No inline scripts or styles, so the server can send a strict CSP.
    assetsInlineLimit: 0,
    sourcemap: false,
  },
  test: {
    environment: "jsdom",
    setupFiles: ["./src/test/setup.ts"],
    include: ["src/**/*.test.{ts,tsx}"],
  },
});
