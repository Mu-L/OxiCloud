/**
 * Batch operations (/api/batch/*). Used for multi-item copy — move and delete
 * already have per-item endpoints the files view loops over, but copy only
 * exists as a batch endpoint on the backend.
 */
import { apiFetch } from '$lib/api/client';
import { getCsrfHeaders } from '$lib/api/csrf';

const JSON_HEADERS = { 'Content-Type': 'application/json' };

async function post(url: string, body: unknown): Promise<void> {
	const res = await apiFetch(url, {
		method: 'POST',
		credentials: 'same-origin',
		headers: { ...JSON_HEADERS, ...getCsrfHeaders() },
		body: JSON.stringify(body)
	});
	if (!res.ok) {
		const e = (await res.json().catch(() => ({}))) as { error?: string; message?: string };
		throw new Error(e.error || e.message || `${url} failed: ${res.status}`);
	}
}

export function copyFiles(fileIds: string[], targetFolderId: string | null): Promise<void> {
	if (fileIds.length === 0) return Promise.resolve();
	return post('/api/batch/files/copy', { file_ids: fileIds, target_folder_id: targetFolderId });
}

export function copyFolders(folderIds: string[], targetFolderId: string | null): Promise<void> {
	if (folderIds.length === 0) return Promise.resolve();
	return post('/api/batch/folders/copy', {
		folder_ids: folderIds,
		target_folder_id: targetFolderId
	});
}
