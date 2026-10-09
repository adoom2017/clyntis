import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import pkg from "./package.json";

export default defineConfig({
  plugins: [react()],
  define: {
    __APP_VERSION__: JSON.stringify(
      process.env.CLYNTIS_APP_VERSION || pkg.version,
    ),
  },
  server: { port: 1420, strictPort: true },
  clearScreen: false,
  test: { environment: "jsdom", setupFiles: ["./tests/setup.ts"] },
});
