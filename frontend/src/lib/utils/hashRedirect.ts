/**
 * Translate an old hash route (`#/...` from the vanilla frontend) into the new
 * SvelteKit path, so existing bookmarks and external links keep working.
 *
 * Returns the new pathname, or null when the hash isn't a recognised route.
 */
export function hashUrlToPath(hash: string): string | null {
	if (!hash.startsWith('#/')) return null;
	const raw = hash.slice(1); // drop the '#'
	const [pathPart] = raw.split('?');
	const segs = pathPart.split('/').filter(Boolean); // e.g. ['files','folder','<id>']

	if (segs.length === 0 || segs[0] === 'files') {
		// #/ , #/files , #/files/folder/<id>/<id>...
		if (segs[1] === 'folder') return `/files/${segs.slice(2).join('/')}`;
		return '/files';
	}

	switch (segs[0]) {
		case 'shared':
			return '/shared';
		case 'sharedwithme':
			return '/shared-with-me';
		case 'recent':
			return '/recent';
		case 'favorites':
			return '/favorites';
		case 'trash':
			return '/trash';
		case 'photos':
			return '/photos';
		case 'music':
			return '/music';
		default:
			return null;
	}
}
