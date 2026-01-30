import { json } from '@sveltejs/kit';
import { auth } from '$lib/server/auth';
import { deleteEnv, deleteSharedEnv, getVaultEnv } from '$lib/server/env-vault';
import { hasShareAccess } from '$lib/server/shares';
import type { RequestHandler } from './$types';

export const DELETE: RequestHandler = async ({ request }) => {
	const session = await auth.api.getSession({
		headers: request.headers
	});

	if (!session || !session.user) {
		return json({ error: 'Unauthorized' }, { status: 401 });
	}

	try {
		const body = await request.json();
		const { vaultPath, keys } = body;

		if (!vaultPath || typeof vaultPath !== 'string') {
			return json({ error: 'vaultPath is required' }, { status: 400 });
		}

		if (!keys || !Array.isArray(keys)) {
			return json({ error: 'keys must be an array' }, { status: 400 });
		}

		const userId = session.user.id;

		// Check if this is user's own folder or a shared folder
		const ownEnvs = await getVaultEnv(userId, vaultPath);
		const hasOwnData = Object.keys(ownEnvs).length > 0;

		let targetUserId = userId;
		let isSharedWrite = false;

		if (!hasOwnData) {
			// Check if user has shared access with write permission
			const shareAccess = await hasShareAccess(userId, vaultPath, 'readwrite');

			if (!shareAccess.hasAccess) {
				// Check if they have read-only access
				const readAccess = await hasShareAccess(userId, vaultPath, 'read');
				if (readAccess.hasAccess) {
					return json(
						{
							error:
								'This folder is shared with read-only access. You cannot delete from it.'
						},
						{ status: 403 }
					);
				}
				return json(
					{ error: 'You do not have access to delete from this vault path' },
					{ status: 403 }
				);
			}

			// Has write access - get the owner ID
			const { getIncomingShares } = await import('$lib/server/shares');
			const shares = await getIncomingShares(userId);
			const matchingShare = shares.find(
				(share) =>
					share.folderPath === vaultPath || vaultPath.startsWith(share.folderPath + ':')
			);

			if (!matchingShare) {
				return json({ error: 'Share access not found' }, { status: 404 });
			}

			targetUserId = matchingShare.ownerId;
			isSharedWrite = true;
		}

		let deletedCount = 0;
		const errors: string[] = [];

		// Delete each key
		for (const key of keys) {
			if (typeof key !== 'string') {
				errors.push(`Invalid key: ${key}`);
				continue;
			}

			try {
				// Construct full key with vault path prefix
				const fullKey = vaultPath ? `${vaultPath}:${key}` : key;

				if (isSharedWrite) {
					// Delete from owner's vault
					await deleteSharedEnv(targetUserId, fullKey);
				} else {
					// Delete from own vault
					await deleteEnv(userId, fullKey);
				}
				deletedCount++;
			} catch (error: any) {
				errors.push(`Failed to delete ${key}: ${error.message}`);
			}
		}

		return json({
			success: true,
			message: `Successfully deleted ${deletedCount} environment variable(s)${isSharedWrite ? ' from shared folder' : ''}`,
			deletedCount,
			errorCount: errors.length,
			errors: errors.length > 0 ? errors : undefined,
			isShared: isSharedWrite
		});
	} catch (error: any) {
		console.error('Delete vault error:', error);
		return json({ error: error.message || 'Invalid request' }, { status: 400 });
	}
};
