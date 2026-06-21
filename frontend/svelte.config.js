import adapter from '@sveltejs/adapter-static';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

/**
 * SvelteKit config — pure SPA via adapter-static.
 *
 * Phase 0: output to the local `build/` dir so the existing `static-dist/`
 * (still produced by build.rs) is untouched. At cutover (Phase 5) the
 * `pages`/`assets` targets switch to `../static-dist` and build.rs stops
 * generating assets.
 *
 * `fallback: 'index.html'` makes every unmatched client route serve the SPA
 * shell, which the Rust web layer will mirror with a ServeFile fallback.
 *
 * @type {import('@sveltejs/kit').Config}
 */
const config = {
	preprocess: vitePreprocess(),
	kit: {
		adapter: adapter({
			// Cutover: emit the SPA into the repo-root `static-dist/` that the Rust
			// web layer serves in release. build.rs no longer generates this dir
			// (gated behind OXICLOUD_LEGACY_ASSETS for rollback).
			pages: '../static-dist',
			assets: '../static-dist',
			fallback: 'index.html',
			precompress: false,
			strict: true
		}),
		// All routes are client-rendered; SSR/prerender are disabled in +layout.ts.
		alias: {
			$lib: './src/lib'
		},
		// Poll `_app/version.json` so an open tab notices a fresh deploy; the root
		// layout reloads itself when it does, instead of silently running stale
		// code after a rebuild (the classic "my fix isn't applied" trap).
		version: {
			pollInterval: 60000
		}
	}
};

export default config;
