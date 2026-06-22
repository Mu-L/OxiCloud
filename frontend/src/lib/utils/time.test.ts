import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { relativeTimeAgo } from './time';

describe('relativeTimeAgo', () => {
	beforeEach(() => {
		vi.useFakeTimers();
		vi.setSystemTime(new Date('2024-06-15T12:00:00Z'));
	});
	afterEach(() => vi.useRealTimers());

	it('returns the empty label for null/undefined/empty', () => {
		expect(relativeTimeAgo(null)).toBe('');
		expect(relativeTimeAgo(undefined)).toBe('');
		expect(relativeTimeAgo('')).toBe('');
		expect(relativeTimeAgo(null, { empty: 'never' })).toBe('never');
	});

	it('handles unparseable input', () => {
		expect(relativeTimeAgo('garbage')).toBe('');
		expect(relativeTimeAgo('garbage', { invalidAsString: true })).toBe('garbage');
	});

	it('formats past times in the largest matching unit', () => {
		expect(relativeTimeAgo(Date.now() - 2 * 31_536_000_000)).toMatch(/year/);
		expect(relativeTimeAgo(Date.now() - 2 * 2_592_000_000)).toMatch(/month/);
		expect(relativeTimeAgo(Date.now() - 2 * 604_800_000)).toMatch(/week/);
		expect(relativeTimeAgo(Date.now() - 3 * 86_400_000)).toMatch(/day/);
		expect(relativeTimeAgo(Date.now() - 3_600_000)).toMatch(/hour/);
		expect(relativeTimeAgo(Date.now() - 120_000)).toMatch(/minute/);
	});

	it('accepts epoch seconds as well as milliseconds', () => {
		expect(relativeTimeAgo(Math.floor((Date.now() - 3_600_000) / 1000))).toMatch(/hour/);
	});

	it('falls back to seconds for very recent timestamps', () => {
		expect(relativeTimeAgo(Date.now() - 5_000)).toMatch(/second/);
	});
});
