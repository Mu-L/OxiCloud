/** Display helpers shared across list views. */

/**
 * Map an `icon_class` (e.g. "fas fa-folder", "fa-file-pdf") to an icon
 * registry name (the FA token without the `fa-` prefix).
 */
export function iconNameFromClass(iconClass: string | undefined | null): string {
	if (!iconClass) return 'file';
	const token = iconClass
		.split(/\s+/)
		.find((c) => c.startsWith('fa-') && c !== 'fa-fw' && c !== 'fa-lg');
	return token ? token.slice(3) : 'file';
}

/** Format a timestamp (epoch seconds/ms or ISO-8601 string) as a local date. */
export function formatDate(value: number | string | null | undefined): string {
	if (value === null || value === undefined) return '';
	let d: Date;
	if (typeof value === 'number') {
		// Heuristic: seconds vs milliseconds.
		d = new Date(value < 1e12 ? value * 1000 : value);
	} else {
		d = new Date(value);
	}
	if (Number.isNaN(d.getTime())) return '';
	return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}
