// @ts-check

/**
 * Address Book model.
 *
 * Provides access to all address books (user-owned + shared + the virtual
 * system book) and their contacts.  Serves as the single source of truth for
 * contact data across the application — sharing dialogs, owner tooltips, etc.
 *
 * Caching strategy
 * ─────────────────
 * • System book  — cached for the whole session (contacts = OxiCloud users,
 *                  changes rarely and requires a page reload to pick up anyway).
 * • User books   — cached on first load; call `invalidate(bookId)` after a
 *                  write (create/update/delete contact) to force a re-fetch.
 *
 * The system book returns 404 when `OXICLOUD_EXPOSE_SYSTEM_USERS` is disabled.
 * In that case `isSystemAvailable()` returns false and all callers degrade
 * gracefully.
 */

/** @import {AddressBookItem, ContactItem} from '../core/types.js' */

/** Sentinel id for the virtual system address book. */
export const SYSTEM_BOOK_ID = 'system';

/** @type {AddressBookItem[] | null} */
let _books = null;

/** @type {Map<string, ContactItem[]>} bookId → contacts (loaded books) */
const _contactCache = new Map();

/** @type {Map<string, Promise<ContactItem[]>>} bookId → in-flight request */
const _inflight = new Map();

/**
 * `null`  = not yet attempted
 * `true`  = loaded successfully at least once
 * `false` = 404 / feature disabled
 * @type {boolean | null}
 */
let _systemAvailable = null;

// ── Address books ─────────────────────────────────────────────────────────────

/**
 * List all address books accessible to the current user.
 * Result is cached for the session.
 * @returns {Promise<AddressBookItem[]>}
 */
async function listBooks() {
    if (_books !== null) return _books;
    const res = await fetch('/api/address-books', { credentials: 'same-origin' });
    if (!res.ok) throw new Error(`addressBook.listBooks: HTTP ${res.status}`);
    _books = /** @type {AddressBookItem[]} */ (await res.json());
    return _books;
}

// ── Contacts ──────────────────────────────────────────────────────────────────

/**
 * List contacts in an address book.
 *
 * Results are cached per book id.  For the system book, a 404 is treated as
 * "feature disabled" — an empty array is returned and `isSystemAvailable()`
 * will report false.
 *
 * @param {string} bookId
 * @param {{ limit?: number, offset?: number }} [opts]
 * @returns {Promise<ContactItem[]>}
 */
async function listContacts(bookId, opts = {}) {
    if (_contactCache.has(bookId)) {
        return /** @type {ContactItem[]} */ (_contactCache.get(bookId));
    }

    if (_inflight.has(bookId)) {
        return /** @type {Promise<ContactItem[]>} */ (_inflight.get(bookId));
    }

    const p = (async () => {
        try {
            const params = new URLSearchParams();
            if (opts.limit !== undefined) params.set('limit', String(opts.limit));
            if (opts.offset !== undefined) params.set('offset', String(opts.offset));
            const qs = params.size ? `?${params}` : '';

            const res = await fetch(`/api/address-books/${encodeURIComponent(bookId)}/contacts${qs}`, {
                credentials: 'same-origin',
                cache: 'default'
            });

            if (res.status === 404 && bookId === SYSTEM_BOOK_ID) {
                _systemAvailable = false;
                _contactCache.set(bookId, []);
                return /** @type {ContactItem[]} */ ([]);
            }

            if (!res.ok) {
                throw new Error(`addressBook.listContacts(${bookId}): HTTP ${res.status}`);
            }

            const contacts = /** @type {ContactItem[]} */ (await res.json());
            _contactCache.set(bookId, contacts);
            if (bookId === SYSTEM_BOOK_ID) _systemAvailable = true;
            return contacts;
        } finally {
            _inflight.delete(bookId);
        }
    })();

    _inflight.set(bookId, p);
    return p;
}

/**
 * Invalidate the contact cache for a given book so the next `listContacts`
 * call re-fetches from the server.  Call after any write operation.
 * @param {string} bookId
 */
function invalidate(bookId) {
    _contactCache.delete(bookId);
}

// ── Search ────────────────────────────────────────────────────────────────────

/**
 * Search contacts across one or more address books.
 *
 * Matching is case-insensitive against the full name, first+last name, and
 * primary email.  Books are fetched and cached on first use.
 *
 * @param {string}   query
 * @param {string[]} [bookIds]  - Books to search.  Defaults to all cached books.
 *                                Pass `[SYSTEM_BOOK_ID]` to restrict to OxiCloud users.
 * @returns {Promise<ContactItem[]>}
 */
async function searchContacts(query, bookIds) {
    const ids = bookIds ?? [..._contactCache.keys()];
    const q = query.toLowerCase().trim();
    if (!q) return [];

    /** @type {ContactItem[]} */
    const results = [];

    for (const id of ids) {
        const contacts = await listContacts(id);
        for (const c of contacts) {
            const fullName = [c.first_name, c.last_name].filter(Boolean).join(' ') || c.full_name || '';
            const primaryEmail = c.email?.find((e) => e.is_primary)?.email ?? c.email?.[0]?.email ?? '';

            if (fullName.toLowerCase().includes(q) || primaryEmail.toLowerCase().includes(q)) {
                results.push(c);
            }
        }
    }

    return results;
}

// ── Status ────────────────────────────────────────────────────────────────────

/**
 * Whether the system address book is (or may be) available.
 * Returns `true` when status is unknown (not yet fetched).
 * Returns `false` only after a confirmed 404.
 * @returns {boolean}
 */
function isSystemAvailable() {
    return _systemAvailable !== false;
}

export const addressBook = {
    listBooks,
    listContacts,
    invalidate,
    searchContacts,
    isSystemAvailable
};
