import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('$lib/api/client', () => ({ apiFetch: vi.fn() }));
vi.mock('$lib/api/csrf', () => ({ getCsrfHeaders: () => ({}) }));

import { apiFetch } from '$lib/api/client';
import { copyFiles, copyFolders } from './batch';

const fetchMock = apiFetch as unknown as ReturnType<typeof vi.fn>;

describe('batch copy', () => {
	beforeEach(() => {
		vi.clearAllMocks();
		fetchMock.mockResolvedValue({ ok: true, status: 200, json: async () => ({}) });
	});

	it('short-circuits on empty input', async () => {
		await copyFiles([], null);
		await copyFolders([], 'x');
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it('posts copy requests for files and folders', async () => {
		await copyFiles(['a'], 't');
		await copyFolders(['b'], null);
		expect(fetchMock).toHaveBeenCalledTimes(2);
		expect(fetchMock).toHaveBeenCalledWith(
			'/api/batch/files/copy',
			expect.objectContaining({ method: 'POST' })
		);
	});

	it('throws the server error/message on failure', async () => {
		fetchMock.mockResolvedValue({ ok: false, status: 400, json: async () => ({ error: 'bad' }) });
		await expect(copyFiles(['a'], 't')).rejects.toThrow('bad');
		fetchMock.mockResolvedValue({ ok: false, status: 500, json: async () => ({}) });
		await expect(copyFolders(['b'], 't')).rejects.toThrow(/failed: 500/);
	});
});
