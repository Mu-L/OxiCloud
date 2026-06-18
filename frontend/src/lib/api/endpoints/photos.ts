/** Photos timeline endpoint — ported from features/library/photos.js. */
import { apiFetch } from '$lib/api/client';
import { getCsrfHeaders } from '$lib/api/csrf';
import type { FileItem } from '$lib/api/types';

export interface PhotoPage {
	items: FileItem[];
	nextCursor: string | null;
}

/** EXIF metadata returned by `/api/files/{id}/metadata` (subset used by the lightbox). */
export interface FileMetadata {
	file_id: string;
	captured_at?: number;
	latitude?: number | null;
	longitude?: number | null;
	camera_make?: string | null;
	camera_model?: string | null;
	orientation?: number | null;
	width?: number | null;
	height?: number | null;
}

/** Result of a batch trash request (200 = all, 206 = partial success). */
export interface BatchTrashResult {
	successful: string[];
	failed: string[];
}

/** Backend `MAX_BATCH_SIZE` — chunk larger selections into separate requests. */
const BATCH_CHUNK_SIZE = 1000;

/**
 * Fetch one page of the photo timeline. The next-page cursor is returned in the
 * `X-Next-Cursor` response header; the page is the last one when fewer than
 * `limit` items come back.
 */
export async function fetchPhotos(limit = 60, before?: string | null): Promise<PhotoPage> {
	let url = `/api/photos?limit=${limit}`;
	if (before) url += `&before=${encodeURIComponent(before)}`;
	const res = await apiFetch(url, { credentials: 'same-origin' });
	if (!res.ok) throw new Error(`photos failed: ${res.status}`);
	const items = (await res.json()) as FileItem[];
	const cursor = res.headers.get('X-Next-Cursor');
	return {
		items: items ?? [],
		nextCursor: cursor && items && items.length >= limit ? cursor : null
	};
}

/** Fetch EXIF metadata for a file. Returns `null` on any error (non-critical). */
export async function fetchFileMetadata(fileId: string): Promise<FileMetadata | null> {
	try {
		const res = await apiFetch(`/api/files/${fileId}/metadata`, { credentials: 'same-origin' });
		if (!res.ok) return null;
		return (await res.json()) as FileMetadata;
	} catch {
		return null;
	}
}

/**
 * Move files to trash in batches via `POST /api/batch/trash`. One request per
 * chunk (up to {@link BATCH_CHUNK_SIZE} ids); 200 = all trashed, 206 = partial.
 * Returns the set of ids that were actually trashed across all chunks.
 */
export async function batchTrash(fileIds: string[]): Promise<Set<string>> {
	const trashed = new Set<string>();
	for (let i = 0; i < fileIds.length; i += BATCH_CHUNK_SIZE) {
		const chunk = fileIds.slice(i, i + BATCH_CHUNK_SIZE);
		const res = await apiFetch('/api/batch/trash', {
			method: 'POST',
			credentials: 'same-origin',
			headers: { 'Content-Type': 'application/json', ...getCsrfHeaders() },
			body: JSON.stringify({ file_ids: chunk, folder_ids: [] })
		});
		// 200 = all trashed, 206 = partial; both carry `successful`.
		if (!res.ok && res.status !== 206) continue;
		const data = (await res.json().catch(() => ({}))) as Partial<BatchTrashResult>;
		const ok = Array.isArray(data?.successful) ? data.successful : chunk;
		for (const id of ok) trashed.add(id);
	}
	return trashed;
}

/**
 * Upload a generated thumbnail blob for a file at a given size. Used by the
 * photos grid to persist client-generated video frames server-side.
 */
export async function uploadThumbnail(
	fileId: string,
	size: 'icon' | 'preview' | 'large',
	blob: Blob,
	contentType = 'image/jpeg'
): Promise<void> {
	await apiFetch(`/api/files/${fileId}/thumbnail/${size}`, {
		method: 'PUT',
		credentials: 'same-origin',
		headers: { ...getCsrfHeaders(), 'Content-Type': contentType },
		body: blob
	});
}
