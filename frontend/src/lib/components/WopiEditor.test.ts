import { it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/svelte';

vi.mock('$lib/api/endpoints/wopi', () => ({ getEditorUrlWithFallback: vi.fn() }));
vi.mock('$lib/utils/errors', () => ({ errorToast: vi.fn() }));

import { getEditorUrlWithFallback } from '$lib/api/endpoints/wopi';
import { errorToast } from '$lib/utils/errors';
import WopiEditor from './WopiEditor.svelte';

const g = getEditorUrlWithFallback as unknown as ReturnType<typeof vi.fn>;
const et = errorToast as unknown as ReturnType<typeof vi.fn>;

beforeEach(() => vi.clearAllMocks());

it('opens, loads the editor URL, and renders the dialog', async () => {
	g.mockResolvedValue({
		editor_url: 'https://wopi/edit',
		access_token: 'tok',
		access_token_ttl: 9999
	});
	render(WopiEditor, { props: { open: true, fileId: 'f1', fileName: 'doc.docx', action: 'edit' } });
	await waitFor(() => expect(g).toHaveBeenCalledWith('f1', 'doc.docx', 'edit'));
	expect(screen.getByTestId('wopi-editor-dialog')).toBeTruthy();
});

it('drops the spinner on an App_LoadingStatus message and closes on UI_Close', async () => {
	g.mockResolvedValue({ editor_url: 'u', access_token: 't', access_token_ttl: 1 });
	const onclose = vi.fn();
	render(WopiEditor, { props: { open: true, fileId: 'f1', fileName: 'd.docx', onclose } });
	await waitFor(() => screen.getByTestId('wopi-editor-dialog'));

	window.dispatchEvent(
		new MessageEvent('message', {
			data: JSON.stringify({
				MessageId: 'App_LoadingStatus',
				Values: { Status: 'Document_Loaded' }
			})
		})
	);
	window.dispatchEvent(
		new MessageEvent('message', { data: JSON.stringify({ MessageId: 'UI_Close' }) })
	);
	await waitFor(() => expect(onclose).toHaveBeenCalled());
});

it('reports a load failure via errorToast', async () => {
	g.mockRejectedValue(new Error('no wopi host'));
	render(WopiEditor, { props: { open: true, fileId: 'f1', fileName: 'd.docx' } });
	await waitFor(() => expect(et).toHaveBeenCalled());
});

it('does not load when closed', () => {
	render(WopiEditor, { props: { open: false, fileId: 'f1', fileName: 'd.docx' } });
	expect(g).not.toHaveBeenCalled();
});
