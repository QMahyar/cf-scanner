import { vitePreprocess } from "@sveltejs/vite-plugin-svelte";

/** @type {import('@sveltejs/vite-plugin-svelte').SvelteConfig} */
export default {
  preprocess: vitePreprocess(),
  compilerOptions: {
    // Every component here uses runes ($state/$derived); never fall back to
    // legacy store auto-subscription, which misfires on plain reactive
    // objects like the shared UI state.
    runes: true,
  },
};
