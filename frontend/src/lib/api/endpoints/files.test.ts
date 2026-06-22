import { describe, it, expect, vi, beforeEach } from 'vitest';
vi.mock('$lib/api/client', () => ({ apiFetch: vi.fn(), apiJson: vi.fn() }));
vi.mock('$lib/api/csrf', () => ({ getCsrfHeaders: () => ({}) }));
import { apiFetch } from '$lib/api/client';
import {
	uploadFile,
	renameFile,
	moveFile,
	deleteFile,
	fileDownloadUrl,
	fileInlineUrl
} from './files';
const f = apiFetch as unknown as ReturnType<typeof vi.fn>;
describe('files endpoint URL builders', () => {
	it('build download/inline URLs', () => {
		expect(fileDownloadUrl('id1')).toContain('id1');
		expect(fileDownloadUrl('id1')).toContain('/api/files/');
		expect(fileInlineUrl('id1')).toContain('id1');
	});
});
describe('files endpoint mutations', () => {
	beforeEach(() => {
		vi.clearAllMocks();
		f.mockResolvedValue({ ok: true, status: 200, json: async () => ({ id: 'x' }) });
	});
	it('call the API for upload/rename/move/delete', async () => {
		const file = new File([new Uint8Array([1])], 'f.txt', { type: 'text/plain' });
		await uploadFile('fid', file).catch(() => {});
		await renameFile('id', 'new').catch(() => {});
		await moveFile('id', 'dest').catch(() => {});
		await deleteFile('id').catch(() => {});
		expect(f).toHaveBeenCalled();
	});
});
