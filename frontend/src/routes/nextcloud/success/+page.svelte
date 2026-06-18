<script lang="ts">
	import { onMount } from 'svelte';
	import Icon from '$lib/icons/Icon.svelte';
	import { t } from '$lib/i18n/index.svelte';

	function closeWindow() {
		window.close();
	}

	onMount(() => {
		// Mirror the legacy flow: auto-close the popup shortly after success so
		// the user is returned to their Nextcloud client without an extra click.
		const timer = setTimeout(closeWindow, 3000);
		return () => clearTimeout(timer);
	});
</script>

<svelte:head><title>{t('nextcloud.success_title', 'Access granted')} · OxiCloud</title></svelte:head
>

<main class="nc-status">
	<Icon name="check" class="nc-status__icon nc-status__icon--ok" />
	<h1>{t('nextcloud.success_title', 'Access granted')}</h1>
	<p>{t('nextcloud.success_body', 'You can now return to your application — it is connected.')}</p>
	<button type="button" class="nc-status__action" onclick={closeWindow}>
		{t('nextcloud.close_window', 'Close Window')}
	</button>
</main>

<style>
	.nc-status {
		min-height: 100vh;
		display: flex;
		flex-direction: column;
		align-items: center;
		justify-content: center;
		gap: 1rem;
		text-align: center;
		padding: 2rem 1rem;
	}

	:global(.nc-status__icon) {
		font-size: 3rem;
	}

	:global(.nc-status__icon--ok) {
		color: var(--color-success-text);
	}

	.nc-status__action {
		margin-top: 0.5rem;
		padding: 0.5rem 1.25rem;
		border: 1px solid var(--color-border);
		border-radius: var(--radius-md);
		background: var(--color-primary);
		color: var(--color-text-light);
		cursor: pointer;
	}
</style>
