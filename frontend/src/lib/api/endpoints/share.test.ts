import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('$lib/api/client', () => ({ apiFetch: vi.fn(), apiJson: vi.fn() }));
vi.mock('$lib/api/csrf', () => ({ getCsrfHeaders: () => ({}) }));

import { apiFetch, apiJson } from '$lib/api/client';
import {
	shareDownloadUrl,
	shareFileUrl,
	shareZipUrl,
	getShareMeta,
	verifySharePassword,
	getShareContents
} from './share';

const fetchMock = apiFetch as unknown as ReturnType<typeof vi.fn>;
const jsonMock = apiJson as unknown as ReturnType<typeof vi.fn>;

describe('share URL builders', () => {
	it('build encoded share URLs', () => {
		expect(shareDownloadUrl('tok en')).toBe('/api/s/tok%20en/download');
		expect(shareFileUrl('t', 'f/1')).toBe('/api/s/t/file/f%2F1');
		expect(shareZipUrl('t')).toBe('/api/s/t/zip');
		expect(shareZipUrl('t', 'fid')).toBe('/api/s/t/zip/fid');
	});
});

describe('share API calls', () => {
	beforeEach(() => {
		vi.clearAllMocks();
		fetchMock.mockResolvedValue({ ok: true, status: 200, json: async () => ({}) });
		jsonMock.mockResolvedValue({});
	});
	it('hit the API for meta / verify / contents', async () => {
		await getShareMeta('t').catch(() => {});
		await verifySharePassword('t', 'pw').catch(() => {});
		await getShareContents('t').catch(() => {});
		expect(fetchMock.mock.calls.length + jsonMock.mock.calls.length).toBeGreaterThan(0);
	});
});

describe('share status branches', () => {
	const resp = (over: Record<string, unknown>) => ({
		ok: false,
		status: 200,
		json: async () => ({}),
		...over
	});
	beforeEach(() => vi.clearAllMocks());

	it('returns ok meta on 200', async () => {
		fetchMock.mockResolvedValue(
			resp({ ok: true, json: async () => ({ item_type: 'folder', item_name: 'Docs' }) })
		);
		expect(await getShareMeta('t')).toEqual({
			status: 'ok',
			data: { item_type: 'folder', item_name: 'Docs' }
		});
	});

	it('maps 401+requiresPassword to a password prompt', async () => {
		fetchMock.mockResolvedValue(
			resp({ status: 401, json: async () => ({ requiresPassword: true }) })
		);
		expect(await getShareMeta('t')).toEqual({ status: 'password' });
	});

	it('maps meta 410 to expired and 404 to invalid', async () => {
		fetchMock.mockResolvedValueOnce(resp({ status: 410 }));
		expect(await getShareMeta('t')).toEqual({ status: 'expired' });
		fetchMock.mockResolvedValueOnce(resp({ status: 404 }));
		expect(await getShareMeta('t')).toEqual({ status: 'invalid' });
	});

	it('verifies a password: true on ok, false on 401', async () => {
		fetchMock.mockResolvedValueOnce(resp({ ok: true }));
		expect(await verifySharePassword('t', 'pw')).toBe(true);
		fetchMock.mockResolvedValueOnce(resp({ status: 401 }));
		expect(await verifySharePassword('t', 'bad')).toBe(false);
	});

	it('lists contents and maps 401→password, 410→expired', async () => {
		fetchMock.mockResolvedValueOnce(
			resp({ ok: true, json: async () => ({ folders: [], files: [] }) })
		);
		expect((await getShareContents('t')).status).toBe('ok');
		fetchMock.mockResolvedValueOnce(resp({ status: 401 }));
		expect((await getShareContents('t')).status).toBe('password');
		fetchMock.mockResolvedValueOnce(resp({ status: 410 }));
		expect((await getShareContents('t', 'fid')).status).toBe('expired');
	});
});
