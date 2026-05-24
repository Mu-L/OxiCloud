// @ts-check

/**
 * Owner tooltip — shows "Shared by: <display name>" when hovering a
 * `.file-item[data-owner-id]` element.
 *
 * Reuses the existing `#path-tooltip` DOM element (same position and style)
 * so no extra CSS is needed.  The tooltip is hidden immediately on mouseleave
 * and the display-name resolution is async-but-usually-instant because
 * `systemUsers` is pre-fetched when the Shared-with-me section is entered.
 *
 * Usage:
 *   ownerTooltip.init(containerEl)    — call after rendering items
 *   ownerTooltip.destroy(containerEl) — call when leaving the section
 */

import { i18n } from '../core/i18n.js';
import { systemUsers } from '../model/systemUsers.js';

// ── Tooltip DOM ───────────────────────────────────────────────────────────────

/** @returns {HTMLElement} */
function _getOrCreateTooltip() {
    let el = document.getElementById('path-tooltip');
    if (!el) {
        el = document.createElement('div');
        el.id = 'path-tooltip';
        el.className = 'path-tooltip hidden';
        document.querySelector('.main-content')?.appendChild(el);
    }
    return el;
}

function _hide() {
    document.getElementById('path-tooltip')?.classList.add('hidden');
}

// ── Event handlers ────────────────────────────────────────────────────────────

/**
 * @param {MouseEvent} e
 */
async function _onEnter(e) {
    const item = /** @type {HTMLElement} */ (e.currentTarget);
    const ownerId = item.dataset.ownerId;
    if (!ownerId) return;

    if (!systemUsers.isAvailable()) return;

    const tooltip = _getOrCreateTooltip();

    // Show immediately with a placeholder so the tooltip appears without lag.
    const label = i18n.t('sharedwithme_sharedBy', 'Shared by');
    tooltip.textContent = `${label}: …`;
    tooltip.classList.remove('hidden');

    // Resolve the name (usually instant from the pre-fetched cache).
    const name = await systemUsers.getDisplayName(ownerId);

    // Guard: don't update if the user already moved away.
    if (!tooltip.classList.contains('hidden')) {
        tooltip.textContent = `${label}: ${name}`;
    }
}

function _onLeave() {
    _hide();
}

// ── Listener registry (WeakMap for leak-free cleanup) ────────────────────────

/**
 * @typedef {{ enter: (e: MouseEvent) => void, leave: () => void }} Handlers
 */

/** @type {WeakMap<HTMLElement, Handlers>} */
const _registry = new WeakMap();

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Attach owner-tooltip listeners to every `.file-item[data-owner-id]`
 * inside `container`.
 * @param {HTMLElement} container
 */
function init(container) {
    for (const item of container.querySelectorAll('.file-item[data-owner-id]')) {
        const el = /** @type {HTMLElement} */ (item);
        if (_registry.has(el)) continue; // already wired

        /** @type {(e: MouseEvent) => void} */
        const enter = (e) => {
            _onEnter(e);
        }; // intentionally discard the Promise
        const leave = () => _onLeave();

        el.addEventListener('mouseenter', enter);
        el.addEventListener('mouseleave', leave);
        _registry.set(el, { enter, leave });
    }
}

/**
 * Remove owner-tooltip listeners from all `.file-item` elements inside
 * `container` and hide any visible tooltip.
 * @param {HTMLElement} container
 */
function destroy(container) {
    for (const item of container.querySelectorAll('.file-item')) {
        const el = /** @type {HTMLElement} */ (item);
        const h = _registry.get(el);
        if (h) {
            el.removeEventListener('mouseenter', h.enter);
            el.removeEventListener('mouseleave', h.leave);
            _registry.delete(el);
        }
    }
    _hide();
}

export const ownerTooltip = { init, destroy };
