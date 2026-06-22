import { it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte';

const { pageState } = vi.hoisted(() => ({
	pageState: { url: new URL('http://localhost/device') }
}));
vi.mock('$app/state', () => ({ page: pageState }));
vi.mock('$lib/api/endpoints/device', () => {
	class DeviceLookupFailure extends Error {}
	return {
		DeviceLookupFailure,
		decideDevice: vi.fn(),
		lookupDeviceCode: vi.fn()
	};
});

import { decideDevice, lookupDeviceCode } from '$lib/api/endpoints/device';
import DevicePage from './+page.svelte';

const m = (fn: unknown) => fn as ReturnType<typeof vi.fn>;
const info = { user_code: 'WXYZ-1234', client_name: 'CLI', scopes: ['files'] };

beforeEach(() => {
	vi.clearAllMocks();
	pageState.url = new URL('http://localhost/device');
});

it('looks up a typed code and shows the review step', async () => {
	m(lookupDeviceCode).mockResolvedValue(info);
	render(DevicePage);
	await screen.findByTestId('device-code-form');
	await fireEvent.input(screen.getByTestId('device-code-input'), {
		target: { value: 'WXYZ-1234' }
	});
	await fireEvent.click(screen.getByTestId('device-continue-btn'));
	await waitFor(() => expect(lookupDeviceCode).toHaveBeenCalledWith('WXYZ-1234'));
	await screen.findByTestId('device-approve-btn');
});

it('approves a device after lookup', async () => {
	m(lookupDeviceCode).mockResolvedValue(info);
	m(decideDevice).mockResolvedValue(undefined);
	render(DevicePage);
	await fireEvent.input(await screen.findByTestId('device-code-input'), {
		target: { value: 'WXYZ-1234' }
	});
	await fireEvent.click(screen.getByTestId('device-continue-btn'));
	await fireEvent.click(await screen.findByTestId('device-approve-btn'));
	await waitFor(() => expect(decideDevice).toHaveBeenCalled());
});

it('shows an error when lookup fails', async () => {
	m(lookupDeviceCode).mockRejectedValue(new Error('nope'));
	render(DevicePage);
	await fireEvent.input(await screen.findByTestId('device-code-input'), {
		target: { value: 'BAD' }
	});
	await fireEvent.click(screen.getByTestId('device-continue-btn'));
	await screen.findByTestId('device-retry-btn');
});
