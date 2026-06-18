/**
 * Theme store — light / dark / auto.
 *
 * Mirrors the established behaviour: persists to the `oxicloud_theme` localStorage
 * key and reflects the choice on `<html data-color-scheme>`. `auto` removes the
 * attribute so the OS `prefers-color-scheme` takes over. The anti-FOUC inline
 * script in app.html applies the stored value before first paint; this store
 * owns runtime changes from the UI.
 */
export type Theme = 'light' | 'dark' | 'auto';

const STORAGE_KEY = 'oxicloud_theme';

function readInitial(): Theme {
	if (typeof localStorage === 'undefined') return 'auto';
	const v = localStorage.getItem(STORAGE_KEY);
	return v === 'light' || v === 'dark' ? v : 'auto';
}

const store = $state<{ theme: Theme }>({ theme: readInitial() });

function apply(theme: Theme): void {
	if (typeof document === 'undefined') return;
	const html = document.documentElement;
	if (theme === 'light' || theme === 'dark') html.setAttribute('data-color-scheme', theme);
	else html.removeAttribute('data-color-scheme');
}

export function setTheme(theme: Theme): void {
	store.theme = theme;
	if (typeof localStorage !== 'undefined') {
		if (theme === 'auto') localStorage.removeItem(STORAGE_KEY);
		else localStorage.setItem(STORAGE_KEY, theme);
	}
	apply(theme);
}

export const theme = {
	get current() {
		return store.theme;
	},
	set: setTheme
};
