import { defineConfig } from "vitest/config";
import { svelte, vitePreprocess } from "@sveltejs/vite-plugin-svelte";

export default defineConfig({
  plugins: [
    svelte({
      preprocess: vitePreprocess(),
      compilerOptions: {
        // Match vite.config.ts: runes-only, never legacy auto-subscription.
        runes: true,
      },
    }),
  ],
  test: {
    environment: "node",
    include: ["src/**/*.test.ts"],
  },
});
