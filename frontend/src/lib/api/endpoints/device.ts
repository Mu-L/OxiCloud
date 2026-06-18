/** Device-authorization (RFC 8628) verification endpoints. */
import { apiFetch } from '$lib/api/client';
import { getCsrfHeaders } from '$lib/api/csrf';

export interface DeviceInfo {
	client_name?: string;
	scopes?: string;
}

/** Distinguishable failure modes the verify page renders differently. */
export type DeviceLookupError = 'unauthorized' | 'not-found' | 'failed';

/** Thrown by lookupDeviceCode so the page can show a tailored message. */
export class DeviceLookupFailure extends Error {
	constructor(readonly kind: DeviceLookupError) {
		super(kind);
		this.name = 'DeviceLookupFailure';
	}
}

/**
 * Look up a device user-code. The backend returns HTTP 200 with `{valid:false}`
 * for unknown/expired codes (NOT a non-2xx), so the body must be inspected — a
 * 2xx alone does not mean the code is good. A 401 means the caller isn't signed
 * in and must authenticate before authorizing a device.
 */
export async function lookupDeviceCode(code: string): Promise<DeviceInfo> {
	const res = await apiFetch(`/api/auth/device/verify?code=${encodeURIComponent(code)}`, {
		credentials: 'same-origin'
	});
	if (res.status === 401) throw new DeviceLookupFailure('unauthorized');
	if (!res.ok) throw new DeviceLookupFailure('failed');
	const data = (await res.json()) as DeviceInfo & { valid?: boolean };
	if (data.valid === false) throw new DeviceLookupFailure('not-found');
	return data;
}

export async function decideDevice(userCode: string, action: 'approve' | 'deny'): Promise<void> {
	const res = await apiFetch('/api/auth/device/verify', {
		method: 'POST',
		credentials: 'same-origin',
		headers: { 'Content-Type': 'application/json', ...getCsrfHeaders() },
		body: JSON.stringify({ user_code: userCode, action })
	});
	if (!res.ok) throw new Error(`device ${action} failed: ${res.status}`);
}
