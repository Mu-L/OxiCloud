import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('$lib/stores/ui.svelte', () => ({ ui: { notify: vi.fn() } }));

import { ui } from '$lib/stores/ui.svelte';
import { errorMessage, errorToast } from './errors';

describe('errorMessage', () => {
	it('returns the message of an Error', () => {
		expect(errorMessage(new Error('boom'))).toBe('boom');
	});
	it('stringifies non-Error values', () => {
		expect(errorMessage('nope')).toBe('nope');
		expect(errorMessage(42)).toBe('42');
		expect(errorMessage(null)).toBe('null');
		expect(errorMessage(undefined)).toBe('undefined');
	});
});

describe('errorToast', () => {
	beforeEach(() => vi.clearAllMocks());
	it('raises an error toast with the normalised message', () => {
		errorToast(new Error('bad'));
		expect(ui.notify).toHaveBeenCalledWith('bad', 'error');
	});
	it('handles non-Error values', () => {
		errorToast('plain');
		expect(ui.notify).toHaveBeenCalledWith('plain', 'error');
	});
});
