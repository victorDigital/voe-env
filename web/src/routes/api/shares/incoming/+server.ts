import { json } from '@sveltejs/kit';
import { auth } from '$lib/server/auth';
import { getIncomingShares } from '$lib/server/shares';
import type { RequestHandler } from './$types';

export const GET: RequestHandler = async ({ request }) => {
	const session = await auth.api.getSession({
		headers: request.headers
	});

	if (!session || !session.user) {
		return json({ error: 'Unauthorized' }, { status: 401 });
	}

	try {
		const shares = await getIncomingShares(session.user.id);

		return json({
			success: true,
			shares: shares.map((share) => ({
				id: share.id,
				folderPath: share.folderPath,
				permission: share.permission,
				vaultPassword: share.vaultPassword,
				sharedBy: {
					email: share.owner.email,
					name: share.owner.name
				},
				createdAt: share.createdAt,
				expiresAt: share.expiresAt
			}))
		});
	} catch (error: any) {
		console.error('Get incoming shares error:', error);
		return json({ error: error.message || 'Failed to get shares' }, { status: 500 });
	}
};
