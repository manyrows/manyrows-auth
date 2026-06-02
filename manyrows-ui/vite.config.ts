import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  resolve: {
    dedupe: ["react", "react-dom"],
  },
  server: {
    proxy: {
      "/admin": "http://localhost:8080",
      "/api": "http://localhost:8080",
    },
  },
  build: {
    rollupOptions: {
      output: {
        // Function form: the object form trips the rollup-types overload under
        // `tsc -b`, and is also what the eventual vite-8/rolldown migration
        // needs. Same effect — these stable deps share one cacheable chunk.
        manualChunks(id) {
          const vendor = [
            "axios", "notistack", "react", "react-dom", "react-router-dom",
            "@mui/material", "@emotion/react", "@emotion/styled",
          ];
          if (vendor.some((p) => id.includes(`/node_modules/${p}/`))) {
            return "vendor";
          }
        },
      },
    },
  },
});