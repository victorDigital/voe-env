import { redirect } from '@sveltejs/kit';
import { listEnv, setEnv, getEnv, deleteEnv, getVaultEnv, getSharedVaultEnv } from '$lib/server/env-vault';
import { hasShareAccess, getIncomingShares } from '$lib/server/shares';

type EnvItem = {
	name: string;
	type: 'folder' | 'key';
	isShared?: boolean;
	sharedBy?: { email: string; name: string };
	permission?: 'read' | 'readwrite';
};

export const load = async ({ locals, url }: any) => {
	// Ensure user is authenticated
	if (!locals.user || !locals.session) {
		throw redirect(302, '/');
	}

	const userId = locals.user.id;
	const path = url.searchParams.get('path') || '';

	// Get user's own items
	const ownItems = await listEnv(userId, path);
	const ownEnvs = await getVaultEnv(userId, path);

	// Check if user has access to shared data at this path
	let sharedEnvs: Record<string, string> = {};
	let shareInfo: {
		isShared: boolean;
		sharedBy?: { email: string; name: string };
		permission?: 'read' | 'readwrite';
		encryptedVaultPassword?: string;
	} = { isShared: false };

	// Get all incoming shares
	const allShares = await getIncomingShares(userId);

	// Check if current path is within a shared folder
	if (path) {
		const shareAccess = await hasShareAccess(userId, path, 'read');

		if (shareAccess.hasAccess) {
			// Get the specific share details
			const matchingShare = allShares.find(
				(share) => share.folderPath === path || path.startsWith(share.folderPath + ':')
			);

			if (matchingShare) {
				// Get shared data from owner
				sharedEnvs = await getSharedVaultEnv(matchingShare.ownerId, path);
				shareInfo = {
					isShared: true,
					sharedBy: matchingShare.owner,
					permission: matchingShare.permission,
					encryptedVaultPassword: matchingShare.encryptedVaultPassword
				};
			}
		}
	}

	// Merge own and shared environments (own takes precedence)
	const encryptedEnvs = { ...sharedEnvs, ...ownEnvs };

	// If shared and no own items, we need to construct items from sharedEnvs
	let items: EnvItem[] = ownItems;
	if (shareInfo.isShared && ownItems.length === 0) {
		// Build items from sharedEnvs keys
		items = Object.keys(sharedEnvs).map((key) => ({
			name: key,
			type: 'key' as const
		}));
	}

	// Add shared folders to items list
	// Find shares that should appear at the current path level
	// This includes:
	// 1. Direct children of current path (share parent === path)
	// 2. Shares that START WITH current path (intermediate navigation)
	const sharesAtThisLevel = allShares.filter((share) => {
		const shareParts = share.folderPath.split(':');
		const pathParts = path ? path.split(':') : [];
		
		if (path === '') {
			// At root level, show shares whose first segment should appear
			return shareParts.length >= 1;
		} else {
			// At a specific path, show shares that:
			// 1. Are direct children (parent === path)
			// 2. Have paths that start with current path (intermediate navigation)
			const shareParent = shareParts.slice(0, -1).join(':');
			if (shareParent === path) {
				return true; // Direct child
			}
			// Check if share path starts with current path (we're navigating towards the share)
			if (share.folderPath.startsWith(path + ':')) {
				return true; // Intermediate path towards share
			}
			return false;
		}
	});

	// Build a map of items by name to avoid duplicates
	const itemsMap = new Map<string, EnvItem>();
	for (const item of items) {
		itemsMap.set(item.name, item);
	}

	// Add or mark shared folders
	for (const share of sharesAtThisLevel) {
		const shareParts = share.folderPath.split(':');
		const pathParts = path ? path.split(':') : [];
		
		// Get the name of the folder at the current level
		const folderName = shareParts[pathParts.length];
		if (!folderName) continue;

		const existingItem = itemsMap.get(folderName);
		if (existingItem) {
			// Mark existing folder as shared
			if (existingItem.type === 'folder') {
				itemsMap.set(folderName, {
					...existingItem,
					isShared: true,
					sharedBy: share.owner,
					permission: share.permission
				});
			}
		} else {
			// Add new shared folder (could be intermediate path or actual shared folder)
			itemsMap.set(folderName, {
				name: folderName,
				type: 'folder' as const,
				isShared: true,
				sharedBy: share.owner,
				permission: share.permission
			});
		}
	}

	items = Array.from(itemsMap.values());

	return {
		session: locals.session,
		user: locals.user,
		path,
		items,
		encryptedEnvs,
		shareInfo
	};
};

export const actions: any = {
	set: async ({ request, locals }: any) => {
		if (!locals.user) throw redirect(302, '/');

		const data = await request.formData();
		const key = data.get('key') as string;
		const encryptedValue = data.get('encryptedValue') as string;
		const path = data.get('path') as string;

		if (!key || !encryptedValue) {
			return { success: false, error: 'Key and encrypted value required' };
		}

		const fullKey = path ? `${path}:${key}` : key;
		const userId = locals.user.id;

		try {
			// Check if this is a shared folder with write access
			const ownEnvs = await getVaultEnv(userId, path);
			const hasOwnData = Object.keys(ownEnvs).length > 0;

			if (!hasOwnData) {
				const shareAccess = await hasShareAccess(userId, path, 'readwrite');
				if (!shareAccess.hasAccess) {
					// Check read-only
					const readAccess = await hasShareAccess(userId, path, 'read');
					if (readAccess.hasAccess) {
						return {
							success: false,
							error: 'This folder is shared with read-only access. You cannot modify it.',
							action: 'set'
						};
					}
					return {
						success: false,
						error: 'You do not have access to modify this folder',
						action: 'set'
					};
				}

				// Has write access - get owner ID
				const shares = await getIncomingShares(userId);
				const matchingShare = shares.find(
					(share) => share.folderPath === path || path.startsWith(share.folderPath + ':')
				);

				if (matchingShare) {
					// Set in owner's vault using shared function
					await setEnv(matchingShare.ownerId, fullKey, encryptedValue);
					return { success: true, action: 'set', isShared: true };
				}
			}

			// Set in own vault
			await setEnv(userId, fullKey, encryptedValue);
			return { success: true, action: 'set' };
		} catch (error) {
			return { success: false, error: 'Failed to set env', action: 'set' };
		}
	},

	get: async ({ request, locals }: any) => {
		if (!locals.user) throw redirect(302, '/');

		const data = await request.formData();
		const fullKey = data.get('fullKey') as string;
		const path = data.get('path') as string;

		if (!fullKey) {
			return { success: false, error: 'Key required' };
		}

		const userId = locals.user.id;

		try {
			// First try to get from own vault
			let encryptedValue = await getEnv(userId, fullKey);

			// If not found, check if it's in a shared folder
			if (!encryptedValue && path) {
				const shareAccess = await hasShareAccess(userId, path, 'read');
				if (shareAccess.hasAccess) {
					const shares = await getIncomingShares(userId);
					const matchingShare = shares.find(
						(share) => share.folderPath === path || path.startsWith(share.folderPath + ':')
					);

					if (matchingShare) {
						// Get from owner's vault - we need to query by ownerId and fullKey
						const { getSharedVaultEnv } = await import('$lib/server/env-vault');
						const sharedEnvs = await getSharedVaultEnv(matchingShare.ownerId, path);
						const keyName = fullKey.split(':').pop() || fullKey;
						encryptedValue = sharedEnvs[keyName] || null;
					}
				}
			}

			return { success: true, encryptedValue, action: 'get' };
		} catch (error: any) {
			return { success: false, error: error.message, action: 'get' };
		}
	},

	delete: async ({ request, locals }: any) => {
		if (!locals.user) throw redirect(302, '/');

		const data = await request.formData();
		const fullKey = data.get('fullKey') as string;
		const path = data.get('path') as string;

		if (!fullKey) {
			return { success: false, error: 'Key required' };
		}

		const userId = locals.user.id;

		try {
			// Check if this is a shared folder with write access
			const ownEnvs = await getVaultEnv(userId, path || '');
			const hasOwnData = Object.keys(ownEnvs).length > 0;

			if (!hasOwnData && path) {
				const shareAccess = await hasShareAccess(userId, path, 'readwrite');
				if (!shareAccess.hasAccess) {
					// Check read-only
					const readAccess = await hasShareAccess(userId, path, 'read');
					if (readAccess.hasAccess) {
						return {
							success: false,
							error: 'This folder is shared with read-only access. You cannot delete from it.',
							action: 'delete'
						};
					}
					return {
						success: false,
						error: 'You do not have access to delete from this folder',
						action: 'delete'
					};
				}

				// Has write access - get owner ID
				const shares = await getIncomingShares(userId);
				const matchingShare = shares.find(
					(share) => share.folderPath === path || path.startsWith(share.folderPath + ':')
				);

				if (matchingShare) {
					// Delete from owner's vault
					await deleteEnv(matchingShare.ownerId, fullKey);
					return { success: true, action: 'delete', isShared: true };
				}
			}

			// Delete from own vault
			await deleteEnv(userId, fullKey);
			return { success: true, action: 'delete' };
		} catch (error) {
			return { success: false, error: 'Failed to delete env', action: 'delete' };
		}
	}
};
