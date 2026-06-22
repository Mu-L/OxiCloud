import { it, expect, vi, beforeEach } from 'vitest';
vi.mock('$lib/api/client', () => ({ apiFetch: vi.fn(), apiJson: vi.fn() }));
vi.mock('$lib/api/csrf', () => ({ getCsrfHeaders: () => ({}) }));
import { apiFetch, apiJson } from '$lib/api/client';
import { searchFiles, searchSuggest, clearSearchCache } from './search';
const f = apiFetch as unknown as ReturnType<typeof vi.fn>;
const j = apiJson as unknown as ReturnType<typeof vi.fn>;
beforeEach(() => {
	vi.clearAllMocks();
	f.mockResolvedValue({ ok: true, status: 200, json: async () => ({}) });
	j.mockResolvedValue({ files: [], folders: [] });
});
it('builds search requests including filters', async () => {
	await searchFiles('q', {
		recursive: true,
		fileTypes: ['mp3', 'wav'],
		minSize: 1,
		maxSize: 9,
		sortBy: 'date'
	}).catch(() => {});
	expect(j).toHaveBeenCalledWith(expect.stringContaining('type=mp3%2Cwav'), expect.anything());
	await searchSuggest('q').catch(() => {});
	await clearSearchCache().catch(() => {});
	expect(f.mock.calls.length + j.mock.calls.length).toBeGreaterThan(1);
});
