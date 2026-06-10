import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "jsdom",
    globals: true,
    clearMocks: true,
    unstubGlobals: true,
    include: ["src/**/*.test.{ts,tsx}"],
  },
});
