import { describe, it, expect } from 'vitest';
import { Selection, useSelection } from './useSelection.svelte';

describe('Selection', () => {
	it('adds idempotently and reports size/empty', () => {
		const s = useSelection();
		expect(s.isEmpty).toBe(true);
		s.add('a');
		s.add('a');
		expect(s.size).toBe(1);
		expect(s.has('a')).toBe(true);
	});
	it('toggles ids on and off', () => {
		const s = new Selection();
		s.toggle('b');
		expect(s.has('b')).toBe(true);
		s.toggle('b');
		expect(s.has('b')).toBe(false);
	});
	it('deletes, replaces, and clears', () => {
		const s = new Selection();
		s.set(['x', 'y', 'z']);
		expect(s.size).toBe(3);
		expect(s.values().sort()).toEqual(['x', 'y', 'z']);
		s.delete('y');
		s.delete('missing');
		expect(s.size).toBe(2);
		s.clear();
		expect(s.isEmpty).toBe(true);
		s.clear(); // no-op when already empty
		expect(s.size).toBe(0);
	});
});
