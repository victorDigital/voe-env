import { json } from '@sveltejs/kit';
import { auth } from '$lib/server/auth';
import { setEnv, setSharedEnv, getVaultEnv } from '$lib/server/env-vault';
import { hasShareAccess } from '$lib/server/shares';
import type { RequestHandler } from './$types';

export const POST: RequestHandler = async ({ request }) => {
	const session = await auth.api.getSession({
		headers: request.headers
	});

	if (!session || !session.user) {
		return json({ error: 'Unauthorized' }, { status: 401 });
	}

	try {
		const body = await request.json();
		const { vaultPath, envs } = body;

		if (!vaultPath || typeof vaultPath !== 'string') {
			return json({ error: 'vaultPath is required' }, { status: 400 });
		}

		if (!envs || typeof envs !== 'object') {
			return json({ error: 'envs must be an object' }, { status: 400 });
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
								'This folder is shared with read-only access. You cannot modify it.'
						},
						{ status: 403 }
					);
				}
				return json(
					{ error: 'You do not have access to modify this vault path' },
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

		let successCount = 0;
		const errors: string[] = [];

		// Upload each env variable
		for (const [key, encryptedValue] of Object.entries(envs)) {
			if (typeof encryptedValue !== 'string') {
				errors.push(`Invalid value for key: ${key}`);
				continue;
			}

			try {
				// Construct full key with vault path prefix
				const fullKey = vaultPath ? `${vaultPath}:${key}` : key;

				if (isSharedWrite) {
					// Push to owner's vault
					await setSharedEnv(targetUserId, fullKey, encryptedValue as string);
				} else {
					// Push to own vault
					await setEnv(userId, fullKey, encryptedValue as string);
				}
				successCount++;
			} catch (error: any) {
				errors.push(`Failed to set ${key}: ${error.message}`);
			}
		}

		return json({
			success: true,
			message: `Successfully uploaded ${successCount} environment variable(s)${isSharedWrite ? ' to shared folder' : ''}`,
			successCount,
			errorCount: errors.length,
			errors: errors.length > 0 ? errors : undefined,
			isShared: isSharedWrite
		});
	} catch (error: any) {
		console.error('Push vault error:', error);
		return json({ error: error.message || 'Invalid request' }, { status: 400 });
	}
};
