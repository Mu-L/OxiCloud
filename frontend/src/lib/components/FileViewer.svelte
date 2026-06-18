<script lang="ts">
	import { apiFetch } from '$lib/api/client';
	import { fileDownloadUrl, fileInlineUrl } from '$lib/api/endpoints/files';
	import { canEditWithWopi } from '$lib/api/endpoints/wopi';
	import type { FileItem } from '$lib/api/types';
	import Icon from '$lib/icons/Icon.svelte';
	import WopiEditor from '$lib/components/WopiEditor.svelte';
	import { t } from '$lib/i18n/index.svelte';

	interface Props {
		open: boolean;
		file: FileItem | null;
		/** Emitted when the viewer (or its embedded editor) closes, so the
		 *  consumer can refresh the file list to pick up saves. */
		onrefresh?: () => void;
	}

	let { open = $bindable(false), file, onrefresh }: Props = $props();

	type Kind = 'image' | 'video' | 'audio' | 'pdf' | 'text' | 'other';

	const IMAGE_EXTS = [
		'jpg',
		'jpeg',
		'png',
		'gif',
		'svg',
		'webp',
		'bmp',
		'ico',
		'heic',
		'heif',
		'avif',
		'tiff'
	];

	let textContent = $state('');
	let textLoading = $state(false);
	let wopiOpen = $state(false);
	let canEdit = $state(false);
	/** Image zoom factor (1 = fit). */
	let zoom = $state(1);
	/** PDF embed fallback engaged when the <object> stays blank ~2s. */
	let pdfFallback = $state(false);
	let pdfObjectEl = $state<HTMLObjectElement | null>(null);

	function isImage(f: FileItem): boolean {
		const m = (f.mime_type ?? '').toLowerCase();
		const ext = (f.name || '').split('.').pop()?.toLowerCase() ?? '';
		return m.startsWith('image/') || IMAGE_EXTS.includes(ext);
	}

	function kindOf(f: FileItem): Kind {
		const m = (f.mime_type ?? '').toLowerCase();
		if (isImage(f)) return 'image';
		if (m.startsWith('video/')) return 'video';
		if (m.startsWith('audio/')) return 'audio';
		if (m === 'application/pdf') return 'pdf';
		if (
			m.startsWith('text/') ||
			m === 'application/json' ||
			m === 'application/xml' ||
			m === 'application/javascript'
		)
			return 'text';
		return 'other';
	}

	const kind = $derived(file ? kindOf(file) : 'other');

	function close() {
		open = false;
		textContent = '';
		zoom = 1;
		pdfFallback = false;
		onrefresh?.();
	}

	function onKeydown(e: KeyboardEvent) {
		if (open && !wopiOpen && e.key === 'Escape') close();
	}

	function zoomBy(factor: number) {
		zoom = Math.max(0.1, Math.min(5, zoom * factor));
	}

	function resetZoom() {
		zoom = 1;
	}

	// Load text content + decide editability/auto-open whenever the file changes.
	$effect(() => {
		if (!open || !file) return;
		const f = file;
		canEdit = false;
		zoom = 1;
		pdfFallback = false;
		const k = kindOf(f);

		// Office docs (WOPI-editable, non-image) open straight in the editor
		// rather than showing "No preview available" with an extra Edit click.
		// Images never route through WOPI even if an editor claims the ext.
		if (k === 'other' && !isImage(f)) {
			void canEditWithWopi(f.name).then((v) => {
				canEdit = v;
				if (v && file === f && open) wopiOpen = true;
			});
		} else {
			void canEditWithWopi(f.name).then((v) => (canEdit = v));
		}

		if (k === 'text') {
			textLoading = true;
			textContent = '';
			apiFetch(fileInlineUrl(f.id), { credentials: 'same-origin' })
				.then((r) => (r.ok ? r.text() : Promise.reject(new Error(`HTTP ${r.status}`))))
				.then((txt) => (textContent = txt.slice(0, 500_000)))
				.catch(() => (textContent = t('files.preview_failed', 'Could not load preview.')))
				.finally(() => (textLoading = false));
		}

		// PDF blank-render guard: if the <object> shows nothing after ~2s,
		// fall back to an <embed> (some browsers refuse <object> for PDFs).
		if (k === 'pdf') {
			const timer = setTimeout(() => {
				const el = pdfObjectEl;
				let blank = false;
				try {
					const doc = el?.contentDocument;
					blank = !doc || doc.body?.innerHTML === '';
				} catch {
					blank = false; // cross-origin: assume it rendered
				}
				if (blank) pdfFallback = true;
			}, 2000);
			return () => clearTimeout(timer);
		}
	});
</script>

<svelte:window onkeydown={onKeydown} />

{#if open && file}
	<!-- svelte-ignore a11y_click_events_have_key_events -->
	<div
		class="fv"
		role="dialog"
		aria-modal="true"
		aria-label={file.name}
		tabindex="-1"
		onclick={(e) => e.target === e.currentTarget && close()}
	>
		<div class="fv__panel">
			<header class="fv__bar">
				<span class="fv__title">{file.name}</span>
				<div class="fv__actions">
					{#if kind === 'image'}
						<div class="fv__zoom" role="group" aria-label={t('viewer.zoom', 'Zoom')}>
							<button
								class="fv__zoom-btn"
								title={t('viewer.zoom_out', 'Zoom out')}
								aria-label={t('viewer.zoom_out', 'Zoom out')}
								onclick={() => zoomBy(0.8)}
							>
								<Icon name="search-minus" />
							</button>
							<button
								class="fv__zoom-btn"
								title={t('viewer.zoom_reset', 'Reset zoom')}
								aria-label={t('viewer.zoom_reset', 'Reset zoom')}
								onclick={resetZoom}
							>
								<Icon name="expand" />
							</button>
							<button
								class="fv__zoom-btn"
								title={t('viewer.zoom_in', 'Zoom in')}
								aria-label={t('viewer.zoom_in', 'Zoom in')}
								onclick={() => zoomBy(1.2)}
							>
								<Icon name="search-plus" />
							</button>
						</div>
					{/if}
					{#if canEdit}
						<button class="btn btn-primary btn-sm" onclick={() => (wopiOpen = true)}>
							<Icon name="pen" />
							{t('files.edit', 'Edit')}
						</button>
					{/if}
					<a class="btn btn-secondary btn-sm" href={fileDownloadUrl(file.id)} download>
						<Icon name="download" />
						{t('common.download', 'Download')}
					</a>
					<a
						class="btn btn-secondary btn-sm"
						href={fileInlineUrl(file.id)}
						target="_blank"
						rel="noreferrer"
					>
						<Icon name="external-link-alt" />
					</a>
					<button class="fv__close" aria-label={t('common.close', 'Close')} onclick={close}>
						<Icon name="times" />
					</button>
				</div>
			</header>

			<div class="fv__body">
				{#if kind === 'image'}
					<img
						class="fv__media fv__image"
						src={fileInlineUrl(file.id)}
						alt={file.name}
						style:transform="scale({zoom})"
					/>
				{:else if kind === 'video'}
					<!-- svelte-ignore a11y_media_has_caption -->
					<video class="fv__media" src={fileInlineUrl(file.id)} controls preload="metadata"></video>
				{:else if kind === 'audio'}
					<audio class="fv__audio" src={fileInlineUrl(file.id)} controls></audio>
				{:else if kind === 'pdf'}
					{#if pdfFallback}
						<embed class="fv__pdf" src={fileInlineUrl(file.id)} type="application/pdf" />
					{:else}
						<object
							bind:this={pdfObjectEl}
							class="fv__pdf"
							data={fileInlineUrl(file.id)}
							type="application/pdf"
							title={file.name}
						>
							<p>{t('files.preview_failed', 'Could not load preview.')}</p>
						</object>
					{/if}
				{:else if kind === 'text'}
					{#if textLoading}
						<p class="fv__status">{t('common.loading', 'Loading…')}</p>
					{:else}
						<pre class="fv__text">{textContent}</pre>
					{/if}
				{:else}
					<div class="fv__status fv__status--center">
						<Icon name="file" class="fv__big-icon" />
						<p>{t('files.no_preview', 'No preview available for this file type.')}</p>
					</div>
				{/if}
			</div>
		</div>
	</div>

	<WopiEditor
		bind:open={wopiOpen}
		fileId={file.id}
		fileName={file.name}
		action="edit"
		onclose={() => {
			onrefresh?.();
			// If the editor was auto-opened for an Office doc, closing it should
			// dismiss the whole viewer (there's nothing to preview behind it).
			if (kind === 'other') close();
		}}
	/>
{/if}

<style>
	.fv {
		position: fixed;
		inset: 0;
		z-index: 1000;
		background: var(--color-overlay, var(--color-overlay-heavy));
		display: flex;
		align-items: center;
		justify-content: center;
		padding: 2rem;
	}

	.fv__panel {
		display: flex;
		flex-direction: column;
		width: min(1100px, 100%);
		height: min(90vh, 100%);
		background: var(--color-bg-surface);
		border-radius: var(--radius-lg, var(--radius-md));
		overflow: hidden;
	}

	.fv__bar {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 1rem;
		padding: 0.6rem 0.9rem;
		border-bottom: 1px solid var(--color-border);
	}

	.fv__title {
		font-weight: var(--weight-semibold, 600);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
		color: var(--color-text-heading);
	}

	.fv__actions {
		display: flex;
		align-items: center;
		gap: 0.4rem;
		flex-shrink: 0;
	}

	.fv__close {
		background: none;
		border: none;
		color: var(--color-text);
		cursor: pointer;
		font-size: 1.1rem;
		padding: 0.25rem 0.5rem;
	}

	.fv__zoom {
		display: inline-flex;
		align-items: center;
		gap: 0.15rem;
		margin-right: 0.3rem;
	}

	.fv__zoom-btn {
		display: grid;
		place-items: center;
		width: 30px;
		height: 30px;
		border: 1px solid var(--color-border);
		border-radius: var(--radius-md);
		background: var(--color-bg-surface);
		color: var(--color-text);
		cursor: pointer;
	}

	.fv__zoom-btn:hover {
		background: var(--color-bg-hover);
	}

	.fv__image {
		transition: transform 0.12s ease;
	}

	.fv__body {
		flex: 1;
		display: flex;
		align-items: center;
		justify-content: center;
		overflow: auto;
		background: var(--color-bg-muted);
	}

	.fv__media {
		max-width: 100%;
		max-height: 100%;
		object-fit: contain;
	}

	.fv__audio {
		width: min(600px, 90%);
	}

	.fv__pdf {
		width: 100%;
		height: 100%;
	}

	.fv__text {
		width: 100%;
		height: 100%;
		margin: 0;
		padding: 1rem;
		overflow: auto;
		white-space: pre-wrap;
		word-break: break-word;
		font-family: var(--font-mono, monospace);
		font-size: var(--text-sm);
		color: var(--color-text);
		background: var(--color-bg-surface);
	}

	.fv__status {
		color: var(--color-text-muted);
	}

	.fv__status--center {
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: 0.75rem;
	}

	:global(.fv__big-icon) {
		font-size: 3rem;
		color: var(--color-text-muted);
	}
</style>
