<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { onMount } from 'svelte';
	import '$lib/styles/app.css';
	import AppShell from '$lib/components/AppShell.svelte';
	import DialogHost from '$lib/components/DialogHost.svelte';
	import Toaster from '$lib/components/Toaster.svelte';
	import { session } from '$lib/stores/session.svelte';
	import { hashUrlToPath } from '$lib/utils/hashRedirect';

	let { children } = $props();

	// Routes reachable without an authenticated session.
	const PUBLIC_PREFIXES = ['/login', '/device', '/s/', '/nextcloud'];

	function isPublic(pathname: string): boolean {
		return PUBLIC_PREFIXES.some((p) => pathname === p || pathname.startsWith(p));
	}

	let ready = $state(false);

	onMount(async () => {
		// Redirect old `#/...` bookmarks to the new path before anything else.
		if (typeof location !== 'undefined' && location.hash.startsWith('#/')) {
			const mapped = hashUrlToPath(location.hash);
			if (mapped) await goto(mapped, { replaceState: true });
		}
		await session.load();
		ready = true;
	});

	// Guard: once the session is known, bounce unauthenticated users off
	// protected routes. Runs client-side only (ssr=false).
	$effect(() => {
		if (!ready) return;
		const path = page.url.pathname;
		if (!session.isAuthenticated && !isPublic(path)) {
			void goto(`/login?redirect=${encodeURIComponent(path)}`, { replaceState: true });
		}
	});
</script>

{#if isPublic(page.url.pathname)}
	{@render children()}
{:else if ready && session.isAuthenticated}
	<AppShell {children} />
{:else if ready}
	{@render children()}
{:else}
	<div class="app-loading" aria-busy="true">Loading…</div>
{/if}

<Toaster />
<DialogHost />

<style>
	.app-loading {
		display: grid;
		place-items: center;
		min-height: 100vh;
		color: var(--color-text-muted);
	}
</style>
