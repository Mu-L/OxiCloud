import { it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte';

const { session, ui } = vi.hoisted(() => ({
	session: { loadHomeFolder: vi.fn(async () => 'home'), homeFolderName: 'Files' },
	ui: { notify: vi.fn() }
}));
vi.mock('$lib/stores/session.svelte', () => ({ session }));
vi.mock('$lib/stores/ui.svelte', () => ({ ui }));
vi.mock('$lib/utils/errors', () => ({ errorToast: vi.fn() }));
vi.mock('$lib/api/endpoints/folders', () => ({ listFolder: vi.fn(), moveFolder: vi.fn() }));
vi.mock('$lib/api/endpoints/files', () => ({ moveFile: vi.fn() }));
vi.mock('$lib/api/endpoints/batch', () => ({ copyFiles: vi.fn(), copyFolders: vi.fn() }));

import { listFolder, moveFolder } from '$lib/api/endpoints/folders';
import { moveFile } from '$lib/api/endpoints/files';
import { copyFiles } from '$lib/api/endpoints/batch';
import MoveDialog from './MoveDialog.svelte';

const m = (fn: unknown) => fn as ReturnType<typeof vi.fn>;
const item = { id: 'f1', name: 'doc.txt', kind: 'file' as const };

function folder(id: string, name: string) {
	return {
		category: 'Folder',
		created_at: 0,
		icon_class: 'fa-folder',
		icon_special_class: '',
		id,
		is_root: false,
		modified_at: 0,
		name,
		owner_id: 'me',
		parent_id: 'home',
		path: '/' + name,
		etag: 'e'
	};
}

beforeEach(() => {
	vi.clearAllMocks();
	m(listFolder).mockResolvedValue({
		folders: [folder('sub1', 'Sub')],
		files: [],
		favoriteIds: [],
		sharedIds: []
	});
});

it('loads the home folder when opened', async () => {
	render(MoveDialog, { props: { open: true, item } });
	await waitFor(() => expect(listFolder).toHaveBeenCalledWith('home'));
	await screen.findByTestId('move-dialog');
});

it('moves the item into the current folder on confirm', async () => {
	m(moveFile).mockResolvedValue(undefined);
	const onmoved = vi.fn();
	render(MoveDialog, { props: { open: true, item, onmoved } });
	await screen.findByTestId('move-dialog-confirm-btn');
	await fireEvent.click(screen.getByTestId('move-dialog-confirm-btn'));
	await waitFor(() => expect(moveFile).toHaveBeenCalledWith('f1', 'home'));
	await waitFor(() => expect(onmoved).toHaveBeenCalled());
});

it('navigates into a subfolder before confirming', async () => {
	m(moveFolder).mockResolvedValue(undefined);
	const folderItem = { id: 'fold9', name: 'Dir', kind: 'folder' as const };
	render(MoveDialog, { props: { open: true, item: folderItem } });
	await fireEvent.click(await screen.findByTestId('move-dialog-folder-sub1'));
	await waitFor(() => expect(listFolder).toHaveBeenCalledWith('sub1'));
	await fireEvent.click(screen.getByTestId('move-dialog-confirm-btn'));
	await waitFor(() => expect(moveFolder).toHaveBeenCalledWith('fold9', 'sub1'));
});

it('copies the item in copy mode', async () => {
	m(copyFiles).mockResolvedValue(undefined);
	render(MoveDialog, { props: { open: true, item, mode: 'copy' } });
	await screen.findByTestId('move-dialog-confirm-btn');
	await fireEvent.click(screen.getByTestId('move-dialog-confirm-btn'));
	await waitFor(() => expect(copyFiles).toHaveBeenCalledWith(['f1'], 'home'));
});
