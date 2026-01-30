import { json } from '@sveltejs/kit';
import { auth } from '$lib/server/auth';
import { getVaultEnv, getSharedVaultEnv } from '$lib/server/env-vault';
import { hasShareAccess } from '$lib/server/shares';
import type { RequestHandler } from './$types';

export const GET: RequestHandler = async ({ request, url }) => {
	const session = await auth.api.getSession({
		headers: request.headers
	});

	if (!session || !session.user) {
		return json({ error: 'Unauthorized' }, { status: 401 });
	}

	try {
		const vaultPath = url.searchParams.get('vaultPath');

		if (!vaultPath || typeof vaultPath !== 'string') {
			return json({ error: 'vaultPath query parameter is required' }, { status: 400 });
		}

		const userId = session.user.id;

		// First, try to get the user's own vault data
		const ownEnvs = await getVaultEnv(userId, vaultPath);

		// If user has their own data at this path, return it
		if (Object.keys(ownEnvs).length > 0) {
			return json({
				success: true,
				message: `Retrieved ${Object.keys(ownEnvs).length} environment variable(s)`,
				envs: ownEnvs,
				isShared: false
			});
		}

		// Check if user has shared access to this path
		const shareAccess = await hasShareAccess(userId, vaultPath, 'read');

		if (!shareAccess.hasAccess) {
			return json(
				{ error: 'You do not have access to this vault path' },
				{ status: 403 }
			);
		}

		// User has shared access - find the owner and get their data
		// We need to get the owner's user ID from the shares table
		// This requires a lookup in hasShareAccess to also return owner info
		// For now, we'll try to get data from all potential owners
		// Actually, let's get the specific share details

		// Get all incoming shares that match this path
		const { getIncomingShares } = await import('$lib/server/shares');
		const shares = await getIncomingShares(userId);

		// Find the matching share
		const matchingShare = shares.find(
			(share) =>
				share.folderPath === vaultPath || vaultPath.startsWith(share.folderPath + ':')
		);

		if (!matchingShare) {
			return json(
				{ error: 'Shared folder access not found' },
				{ status: 404 }
			);
		}

		// Get the shared data from the owner's vault
		const sharedEnvs = await getSharedVaultEnv(matchingShare.ownerId, vaultPath);

		return json({
			success: true,
			message: `Retrieved ${Object.keys(sharedEnvs).length} shared environment variable(s)`,
			envs: sharedEnvs,
			isShared: true,
			sharedBy: matchingShare.owner,
			permission: matchingShare.permission,
			vaultPassword: matchingShare.vaultPassword
		});
	} catch (error: any) {
		console.error('Pull vault error:', error);
		return json({ error: error.message || 'Internal server error' }, { status: 500 });
	}
};
