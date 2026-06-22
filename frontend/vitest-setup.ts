import '@testing-library/jest-dom/vitest';

// jsdom lacks ResizeObserver / IntersectionObserver, which several list and
// virtualization components (ResourceList, VirtualList, photos grid) construct
// on mount. Provide inert stubs so component tests can render them.
class StubObserver {
	observe(): void {}
	unobserve(): void {}
	disconnect(): void {}
	takeRecords(): [] {
		return [];
	}
}

const g = globalThis as Record<string, unknown>;
if (!g.ResizeObserver) g.ResizeObserver = StubObserver;
if (!g.IntersectionObserver) g.IntersectionObserver = StubObserver;
if (!g.scrollTo) g.scrollTo = () => {};

// Node 24+ ships a native global `localStorage`/`sessionStorage` (Web Storage
// API) that is unusable without a backing file and shadows jsdom's storage in
// bare-global access — so `localStorage` reads as undefined in some test files
// on newer Node. Install a deterministic in-memory implementation so storage
// behaves identically across Node versions and is fresh for every test file.
class MemoryStorage {
	private store = new Map<string, string>();
	get length(): number {
		return this.store.size;
	}
	clear(): void {
		this.store.clear();
	}
	getItem(key: string): string | null {
		return this.store.has(key) ? (this.store.get(key) as string) : null;
	}
	key(index: number): string | null {
		return [...this.store.keys()][index] ?? null;
	}
	removeItem(key: string): void {
		this.store.delete(key);
	}
	setItem(key: string, value: string): void {
		this.store.set(key, String(value));
	}
}
for (const name of ['localStorage', 'sessionStorage']) {
	try {
		Object.defineProperty(globalThis, name, {
			configurable: true,
			writable: true,
			value: new MemoryStorage() as unknown as Storage
		});
	} catch {
		g[name] = new MemoryStorage() as unknown as Storage;
	}
}
