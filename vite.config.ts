// @lovable.dev/vite-tanstack-config already includes the following — do NOT add them manually
// or the app will break with duplicate plugins:
//   - TanStack devtools (dev-only, first), tanstackStart, viteReact, tailwindcss, tsConfigPaths,
//     nitro (build-only using cloudflare as a default target), VITE_* env injection, @ path alias,
//     React/TanStack dedupe, error logger plugins, and sandbox detection (port/host/strictPort).
// You can pass additional config via defineConfig({ vite: { ... }, etc... }) if needed.
import { defineConfig } from "@lovable.dev/vite-tanstack-config";

export default defineConfig({
  tanstackStart: {
    // Redirect TanStack Start's bundled server entry to src/server.ts (our SSR error wrapper).
    // nitro/vite builds from this
    server: { entry: "server" },
  },
  // Deploy target: Netlify. Inside the Lovable sandbox the build is pinned to
  // cloudflare-module regardless (preview keeps running on Cloudflare); outside
  // the sandbox — i.e. Netlify's CI — this hard-pins Nitro to the `netlify`
  // preset, which emits server functions to `.netlify/functions-internal` and
  // static assets to `dist/`. See netlify.toml (publish = "dist").
  nitro: { preset: "netlify" },
});
