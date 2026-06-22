import { it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte';
import { createRawSnippet } from 'svelte';
import Modal from './Modal.svelte';

const children = createRawSnippet(() => ({
	render: () => '<div data-testid="modal-body">content</div>'
}));

it('renders the title and children when open', () => {
	render(Modal, { props: { open: true, title: 'My dialog', children } });
	expect(screen.getByTestId('modal')).toBeTruthy();
	expect(screen.getByText('My dialog')).toBeTruthy();
	expect(screen.getByTestId('modal-body')).toBeTruthy();
});

it('does not render when closed', () => {
	render(Modal, { props: { open: false, title: 'Hidden', children } });
	expect(screen.queryByTestId('modal')).toBeNull();
});

it('invokes onclose when the close button is clicked', async () => {
	const onclose = vi.fn();
	render(Modal, { props: { open: true, title: 'X', onclose, children } });
	await fireEvent.click(screen.getByTestId('modal-close-btn'));
	expect(onclose).toHaveBeenCalled();
});

it('closes on Escape', async () => {
	const onclose = vi.fn();
	render(Modal, { props: { open: true, title: 'X', onclose, children } });
	await fireEvent.keyDown(window, { key: 'Escape' });
	expect(onclose).toHaveBeenCalled();
});
