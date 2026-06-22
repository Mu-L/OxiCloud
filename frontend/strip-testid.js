/**
 * Svelte markup preprocessor that strips test-only `data-testid` attributes at
 * compile time for production builds.
 *
 * The attribute name, value, and any `{expression}` are removed from the
 * template *before* Svelte compiles it, so production output carries no trace —
 * neither in the rendered DOM nor in the JS bundle (no `'data-testid'` string
 * and no attribute-setting call survive). A runtime guard could only blank the
 * value; this removes the attribute outright.
 *
 * The attribute is kept intact when:
 *   - `VITE_E2E=1` is set (the e2e image / `just fe-build-e2e` build), or
 *   - the build is not a production build (the `vite dev` server),
 * so Playwright and `playwright codegen` can rely on `getByTestId`.
 *
 * Only the markup *between* `<script>`/`<style>` blocks is scanned, so the token
 * `data-testid` appearing inside component logic or styles is never touched.
 */

const ATTR = 'data-testid';

/** Strip only for production builds that didn't opt into test ids. */
function shouldStrip() {
	if (process.env.VITE_E2E === '1') return false;
	return process.env.NODE_ENV === 'production';
}

/** @returns {import('svelte/compiler').PreprocessorGroup} */
export function stripTestId() {
	return {
		name: 'strip-testid',
		markup({ content }) {
			if (!shouldStrip() || !content.includes(ATTR)) return;
			return { code: stripOutsideBlocks(content) };
		}
	};
}

/** Run the attribute removal on markup only, leaving `<script>`/`<style>` verbatim. */
function stripOutsideBlocks(source) {
	const blockRe = /<(script|style)\b[^>]*>[\s\S]*?<\/\1>/gi;
	let result = '';
	let last = 0;
	let m;
	while ((m = blockRe.exec(source)) !== null) {
		result += removeAttr(source.slice(last, m.index));
		result += m[0];
		last = m.index + m[0].length;
	}
	result += removeAttr(source.slice(last));
	return result;
}

/**
 * Remove every `data-testid` attribute occurrence from a markup fragment,
 * handling `="literal"`, `='literal'`, `={balanced expression}` (respecting
 * nested braces and string literals), unquoted values, and the bare boolean
 * form. One preceding space is consumed so no double-space is left behind.
 */
function removeAttr(markup) {
	let out = '';
	let i = 0;
	while (i < markup.length) {
		const idx = markup.indexOf(ATTR, i);
		if (idx === -1) {
			out += markup.slice(i);
			break;
		}
		const prev = markup[idx - 1];
		const after = markup[idx + ATTR.length];
		const boundaryBefore = prev === undefined || /\s/.test(prev);
		const boundaryAfter = after === undefined || after === '=' || /[\s/>]/.test(after);
		if (!boundaryBefore || !boundaryAfter) {
			out += markup.slice(i, idx + ATTR.length);
			i = idx + ATTR.length;
			continue;
		}
		// Emit up to the attribute, dropping one leading whitespace char if present.
		const cut = prev !== undefined && /\s/.test(prev) ? idx - 1 : idx;
		out += markup.slice(i, cut);
		// Advance past the attribute and its value (if any).
		let j = idx + ATTR.length;
		if (markup[j] === '=') {
			j++;
			const q = markup[j];
			if (q === '"' || q === "'") {
				j++;
				while (j < markup.length && markup[j] !== q) j++;
				j++; // consume the closing quote
			} else if (q === '{') {
				let depth = 0;
				while (j < markup.length) {
					const c = markup[j];
					if (c === '"' || c === "'" || c === '`') {
						const sq = c;
						j++;
						while (j < markup.length && markup[j] !== sq) {
							if (markup[j] === '\\') j++;
							j++;
						}
					} else if (c === '{') {
						depth++;
					} else if (c === '}') {
						depth--;
						if (depth === 0) {
							j++;
							break;
						}
					}
					j++;
				}
			} else {
				while (j < markup.length && !/[\s/>]/.test(markup[j])) j++;
			}
		}
		i = j;
	}
	return out;
}
