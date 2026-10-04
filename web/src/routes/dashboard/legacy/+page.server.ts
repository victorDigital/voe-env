import { error, redirect } from '@sveltejs/kit';
import { getAllEnv } from '#lib/server/env-vault.ts';
import { getIncomingShares } from '#lib/server/shares.ts';
import type { PageServerLoad } from './$types';
export const load: PageServerLoad = async ({ locals, url }) => {
	if (!locals.user) redirect(303, '/login');
	const path = url.searchParams.get('path') || '';
	const ownerId = url.searchParams.get('owner') || locals.user.id;
	const incoming = await getIncomingShares(locals.user.id);
	const share =
		ownerId === locals.user.id
			? null
			: incoming.find(
					(s) =>
						s.ownerId === ownerId && (path === s.folderPath || path.startsWith(s.folderPath + ':'))
				);
	if (ownerId !== locals.user.id && !share)
		error(403, 'This archived folder is not shared with you');
	const all = await getAllEnv(ownerId);
	const prefix = path ? path + ':' : '';
	const items = new Map<string, 'folder' | 'key'>();
	const encryptedEnvs: Record<string, string> = {};
	for (const [fullKey, value] of Object.entries(all)) {
		if (!fullKey.startsWith(prefix)) continue;
		const parts = fullKey.slice(prefix.length).split(':');
		const name = parts[0];
		if (parts.length > 1) items.set(name, 'folder');
		else {
			if (!items.has(name)) items.set(name, 'key');
			encryptedEnvs[name] = value;
		}
	}
	return {
		path,
		ownerId,
		shareRoot: share?.folderPath,
		encryptedVaultPassword: share?.encryptedVaultPassword,
		items: [...items].map(([name, type]) => ({ name, type })),
		encryptedEnvs,
		incoming: incoming.map((s) => ({
			ownerId: s.ownerId,
			path: s.folderPath,
			owner: s.owner.name || s.owner.email
		}))
	};
};
