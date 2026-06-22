import { describe, it, expect, vi, beforeEach } from 'vitest';
import { gridColumns } from './grid';

function mockMatchMedia(matches: boolean) {
	vi.stubGlobal(
		'matchMedia',
		vi.fn().mockReturnValue({
			matches,
			media: '',
			addEventListener: vi.fn(),
			removeEventListener: vi.fn()
		})
	);
}

describe('gridColumns', () => {
	beforeEach(() => mockMatchMedia(false));

	it('returns 1 for non-positive width', () => {
		expect(gridColumns(0)).toBe(1);
		expect(gridColumns(-100)).toBe(1);
	});

	it('computes columns at desktop sizing (cardMin 200, gap 20)', () => {
		expect(gridColumns(220)).toBe(1); // floor(240/220)
		expect(gridColumns(440)).toBe(2); // floor(460/220)
		expect(gridColumns(900)).toBe(4); // floor(920/220)
	});

	it('uses mobile sizing when the phone media query matches', () => {
		mockMatchMedia(true);
		expect(gridColumns(300)).toBe(2); // floor(308/148)
		expect(gridColumns(600)).toBe(4); // floor(608/148)
	});
});
