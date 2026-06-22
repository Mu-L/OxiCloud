import { it, expect, vi, beforeEach } from 'vitest';
import { useVirtualWindow } from './useVirtualWindow.svelte';

beforeEach(() => {
	vi.stubGlobal(
		'ResizeObserver',
		class {
			observe() {}
			unobserve() {}
			disconnect() {}
		}
	);
	vi.stubGlobal('requestAnimationFrame', (cb: FrameRequestCallback) => {
		cb(0);
		return 0;
	});
});

it('starts at zero, observes a root, remeasures, and tears down', () => {
	const vw = useVirtualWindow();
	expect(vw.aboveBy).toBe(0);
	expect(vw.viewportH).toBe(0);

	const root = document.createElement('div');
	document.body.appendChild(root);
	const teardown = vw.observe(root);
	expect(typeof teardown).toBe('function');
	vw.remeasure();
	teardown();
	root.remove();
});
