import { describe, it, expect } from 'vitest';
import { iconNameFromClass, formatDate } from './display';

describe('iconNameFromClass', () => {
	it('extracts the fa token without its prefix', () => {
		expect(iconNameFromClass('fas fa-folder')).toBe('folder');
		expect(iconNameFromClass('fa-file-pdf')).toBe('file-pdf');
	});
	it('skips fa-fw / fa-lg modifier tokens', () => {
		expect(iconNameFromClass('fa-fw fa-image')).toBe('image');
		expect(iconNameFromClass('fa-lg fa-music')).toBe('music');
	});
	it('falls back to "file" for missing or unrecognised input', () => {
		expect(iconNameFromClass(null)).toBe('file');
		expect(iconNameFromClass(undefined)).toBe('file');
		expect(iconNameFromClass('')).toBe('file');
		expect(iconNameFromClass('no-fa-token-here')).toBe('file');
	});
});

describe('formatDate', () => {
	it('formats epoch seconds and milliseconds', () => {
		expect(formatDate(1_700_000_000)).toMatch(/\d{4}/); // seconds
		expect(formatDate(1_700_000_000_000)).toMatch(/\d{4}/); // ms
	});
	it('formats ISO-8601 strings', () => {
		expect(formatDate('2024-01-15')).toMatch(/2024/);
	});
	it('returns empty string for null/undefined/invalid', () => {
		expect(formatDate(null)).toBe('');
		expect(formatDate(undefined)).toBe('');
		expect(formatDate('definitely not a date')).toBe('');
	});
});
