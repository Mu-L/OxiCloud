import { it, expect, vi } from 'vitest';
import { useOwnerCache } from './useOwnerCache.svelte';

it('resolves names in parallel, dedupes, skips nullish, and caches', async () => {
	const resolver = vi.fn(async (id: string) => `Name-${id}`);
	const c = useOwnerCache(resolver);
	expect(c.name(null)).toBeNull();
	expect(c.name('u1')).toBeNull();
	expect(c.label('u1')).toBe('u1');

	await c.resolve(['u1', 'u2', null, undefined, 'u1']);
	expect(resolver).toHaveBeenCalledTimes(2);
	expect(c.name('u1')).toBe('Name-u1');
	expect(c.label('u2')).toBe('Name-u2');
	expect(c.names.u1).toBe('Name-u1');

	await c.resolve(['u1']); // already cached → no extra calls
	expect(resolver).toHaveBeenCalledTimes(2);
});
