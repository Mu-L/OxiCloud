import { it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/svelte';

const { goto, pageState } = vi.hoisted(() => ({
	goto: vi.fn(),
	pageState: { url: new URL('http://localhost/search?q=report') }
}));
vi.mock('$app/navigation', () => ({ goto }));
vi.mock('$app/state', () => ({ page: pageState }));
vi.mock('$lib/api/endpoints/search', () => ({ searchFiles: vi.fn() }));
vi.mock('$lib/api/endpoints/files', () => ({ fileInlineUrl: () => '/in' }));

import { searchFiles } from '$lib/api/endpoints/search';
import SearchPage from './+page.svelte';

const m = (fn: unknown) => fn as ReturnType<typeof vi.fn>;

beforeEach(() => {
	vi.clearAllMocks();
	pageState.url = new URL('http://localhost/search?q=report');
	m(searchFiles).mockResolvedValue({ files: [], folders: [], total: 0 });
});

it('runs a search from the q query parameter on mount', async () => {
	render(SearchPage);
	await waitFor(() => expect(searchFiles).toHaveBeenCalled());
	expect(m(searchFiles).mock.calls[0][0]).toBe('report');
});

it('does not search when there is no query', async () => {
	pageState.url = new URL('http://localhost/search');
	render(SearchPage);
	// Give the reactive effect a tick to (not) fire.
	await Promise.resolve();
	expect(searchFiles).not.toHaveBeenCalled();
});

it('surfaces a search error', async () => {
	m(searchFiles).mockRejectedValue(new Error('search boom'));
	render(SearchPage);
	await waitFor(() => expect(searchFiles).toHaveBeenCalled());
	await waitFor(() => expect(screen.getByText('search boom')).toBeTruthy());
});
