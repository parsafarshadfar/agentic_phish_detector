import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  base: "/agenticphishdetector/",
  build: {
    outDir: "dist",
  },
  server: {
    proxy: {
      "/api": {
        target: "http://localhost:8000",
        changeOrigin: true,
        headers: {
          "X-Worker-Token": "REPLACE_WITH_A_STRONG_RANDOM_SECRET"
        }
      },
    },
  },
});
