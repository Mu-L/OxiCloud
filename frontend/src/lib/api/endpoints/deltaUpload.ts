/**
 * Delta upload ("upload only what changed") — ported from
 * features/files/deltaUpload.js. Main-thread orchestrator for
 * `/static/workers/deltaWorker.js`, which runs FastCDC chunking + BLAKE3
 * (the same WASM crate/params as the server) off the UI thread, negotiates
 * which chunks the server already has, uploads only the missing ones, and
 * commits. Any failure resolves `null` so the caller falls back to a plain
 * byte upload — delta is an optimization, never a gate.
 */
import { getCsrfToken } from '$lib/api/csrf';

/** Files smaller than this skip delta: the round-trips cost more than the bytes. */
export const DELTA_UPLOAD_MIN_SIZE = 8 * 1024 * 1024;

const DELTA_WORKER_URL = '/workers/deltaWorker.js';
const DELTA_TIMEOUT_BASE_MS = 120_000;
const DELTA_TIMEOUT_PER_GB_MS = 90_000;

export interface DeltaUploadAnswer {
	ok: boolean;
	data?: unknown;
	errorMsg?: string;
	isQuotaError?: boolean;
	/** Bytes NOT transferred thanks to dedup. */
	savedBytes?: number;
}

/** `false` once the environment proved unable to run the worker/WASM. */
let usable: boolean | null = null;

interface ProgressMsg {
	type: 'progress';
	reusedBytes: number;
	uploadedBytes: number;
	totalBytes: number;
}
interface FallbackMsg {
	type: 'fallback';
	reason?: string;
}
interface DoneMsg {
	type: 'done';
	status: number;
	body?: { message?: string; error?: string; still_missing?: unknown };
}
type WorkerMsg = ProgressMsg | FallbackMsg | DoneMsg;

/**
 * Try to upload `file` through the delta protocol. Resolves `null` whenever
 * the plain byte upload should proceed (too small, environment unusable, any
 * transport/protocol failure). `onProgress` receives 0–99 while transferring.
 */
export function tryDeltaUpload(
	file: File,
	folderId: string | null | undefined,
	onProgress?: (pct: number) => void
): Promise<DeltaUploadAnswer | null> {
	if (
		!folderId ||
		file.size < DELTA_UPLOAD_MIN_SIZE ||
		usable === false ||
		typeof Worker === 'undefined'
	) {
		return Promise.resolve(null);
	}

	return new Promise((resolve) => {
		let worker: Worker;
		try {
			worker = new Worker(DELTA_WORKER_URL, { type: 'module' });
		} catch {
			usable = false;
			resolve(null);
			return;
		}

		const sizeGB = file.size / (1024 * 1024 * 1024);
		const timeoutMs = DELTA_TIMEOUT_BASE_MS + Math.ceil(sizeGB) * DELTA_TIMEOUT_PER_GB_MS;
		let savedBytes = 0;

		const settle = (answer: DeltaUploadAnswer | null) => {
			clearTimeout(timer);
			worker.terminate();
			resolve(answer);
		};
		const timer = setTimeout(() => settle(null), timeoutMs);

		worker.onmessage = (event: MessageEvent<WorkerMsg>) => {
			const msg = event.data;
			if (msg.type === 'progress') {
				savedBytes = msg.reusedBytes;
				if (onProgress && msg.totalBytes > 0) {
					const pct = Math.min(
						99,
						Math.round((100 * (msg.reusedBytes + msg.uploadedBytes)) / msg.totalBytes)
					);
					onProgress(pct);
				}
				return;
			}
			if (msg.type === 'fallback') {
				settle(null);
				return;
			}
			if (msg.type === 'done') {
				if (msg.status === 201 || msg.status === 200) {
					settle({ ok: true, data: msg.body, savedBytes });
					return;
				}
				const errorMsg =
					msg.body?.message || msg.body?.error || `Delta upload failed (HTTP ${msg.status})`;
				if (msg.status === 507) {
					settle({ ok: false, isQuotaError: true, errorMsg });
					return;
				}
				if (msg.status === 409 && !msg.body?.still_missing) {
					settle({ ok: false, errorMsg });
					return;
				}
				settle(null);
			}
		};
		worker.onerror = () => {
			usable = false;
			settle(null);
		};

		worker.postMessage({ file, folderId, name: file.name, csrfToken: getCsrfToken() || '' });
	});
}
