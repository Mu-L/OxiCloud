import { describe, it, expect, beforeEach } from 'vitest';
import { theme, setTheme } from './theme.svelte';

describe('theme store', () => {
	beforeEach(() => {
		localStorage.clear();
		document.documentElement.removeAttribute('data-color-scheme');
	});
	it('sets light/dark, persists, and reflects on <html>', () => {
		setTheme('light');
		expect(theme.current).toBe('light');
		expect(localStorage.getItem('oxicloud_theme')).toBe('light');
		expect(document.documentElement.getAttribute('data-color-scheme')).toBe('light');
		setTheme('dark');
		expect(document.documentElement.getAttribute('data-color-scheme')).toBe('dark');
		expect(localStorage.getItem('oxicloud_theme')).toBe('dark');
	});
	it('auto clears storage and removes the attribute', () => {
		setTheme('dark');
		setTheme('auto');
		expect(theme.current).toBe('auto');
		expect(localStorage.getItem('oxicloud_theme')).toBeNull();
		expect(document.documentElement.hasAttribute('data-color-scheme')).toBe(false);
	});
	it('theme.set is an alias for setTheme', () => {
		theme.set('light');
		expect(theme.current).toBe('light');
	});
});
