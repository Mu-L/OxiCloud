import { it, expect, beforeEach } from 'vitest';
import { dialogs, confirmDialog, promptDialog } from './dialogs.svelte';

beforeEach(() => {
	// Drain any leftover dialog so each test starts clean.
	while (dialogs.current && !dialogs.busy) dialogs.cancel();
});

it('confirm resolves true and prompt resolves its value', async () => {
	const c = confirmDialog({ title: 'Confirm', message: 'ok?' });
	expect(dialogs.current?.kind).toBe('confirm');
	dialogs.resolve(true);
	await expect(c).resolves.toBe(true);

	const p = promptDialog({ title: 'Name' });
	dialogs.resolve('hello');
	await expect(p).resolves.toBe('hello');
});

it('cancel resolves confirm=false and prompt=null', async () => {
	const c = confirmDialog({ title: 'Confirm', message: 'x' });
	dialogs.cancel();
	await expect(c).resolves.toBe(false);
	const p = promptDialog({ title: 'y' });
	dialogs.cancel();
	await expect(p).resolves.toBeNull();
});

it('runs a successful action then resolves', async () => {
	let ran = false;
	const c = confirmDialog({
		title: 'Confirm',
		message: 'x',
		action: async () => {
			ran = true;
		}
	});
	await dialogs.resolve(true);
	expect(ran).toBe(true);
	await expect(c).resolves.toBe(true);
});

it('keeps the dialog open with an inline error when the action fails', async () => {
	const c = confirmDialog({
		title: 'Confirm',
		message: 'x',
		action: async () => {
			throw new Error('boom');
		}
	});
	await dialogs.resolve(true);
	expect(dialogs.error).toBe('boom');
	expect(dialogs.current).not.toBeNull();
	dialogs.cancel(); // recover
	await expect(c).resolves.toBe(false);
});

it('queues a second dialog behind the first', async () => {
	const p1 = confirmDialog({ title: 'Confirm', message: '1' });
	const p2 = confirmDialog({ title: 'Confirm', message: '2' });
	expect(dialogs.current?.opts.message).toBe('1');
	dialogs.resolve(true);
	await p1;
	expect(dialogs.current?.opts.message).toBe('2');
	dialogs.resolve(true);
	await p2;
	expect(dialogs.current).toBeNull();
});
