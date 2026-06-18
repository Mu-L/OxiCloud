import { describe, expect, it } from 'vitest';
import { hashUrlToPath } from './hashRedirect';

describe('hashUrlToPath', () => {
	it('maps root and files', () => {
		expect(hashUrlToPath('#/')).toBe('/files');
		expect(hashUrlToPath('#/files')).toBe('/files');
	});

	it('maps folder deep links to the new path', () => {
		expect(hashUrlToPath('#/files/folder/abc')).toBe('/files/abc');
		expect(hashUrlToPath('#/files/folder/abc/def')).toBe('/files/abc/def');
	});

	it('maps the named sections', () => {
		expect(hashUrlToPath('#/shared')).toBe('/shared');
		expect(hashUrlToPath('#/sharedwithme')).toBe('/shared-with-me');
		expect(hashUrlToPath('#/recent')).toBe('/recent');
		expect(hashUrlToPath('#/favorites')).toBe('/favorites');
		expect(hashUrlToPath('#/trash')).toBe('/trash');
		expect(hashUrlToPath('#/photos')).toBe('/photos');
		expect(hashUrlToPath('#/music')).toBe('/music');
	});

	it('ignores query strings in the hash', () => {
		expect(hashUrlToPath('#/recent?foo=bar')).toBe('/recent');
	});

	it('returns null for non-legacy or unknown hashes', () => {
		expect(hashUrlToPath('')).toBeNull();
		expect(hashUrlToPath('#section')).toBeNull();
		expect(hashUrlToPath('#/unknown')).toBeNull();
	});
});
