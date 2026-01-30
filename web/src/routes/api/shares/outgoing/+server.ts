import { json } from '@sveltejs/kit';
import { auth } from '$lib/server/auth';
import { getOutgoingShares } from '$lib/server/shares';
import type { RequestHandler } from './$types';

export const GET: RequestHandler = async ({ request }) => {
	const session = await auth.api.getSession({
		headers: request.headers
	});

	if (!session || !session.user) {
		return json({ error: 'Unauthorized' }, { status: 401 });
	}

	try {
		const shares = await getOutgoingShares(session.user.id);

		return json({
			success: true,
			shares: shares.map((share) => ({
				id: share.id,
				folderPath: share.folderPath,
				permission: share.permission,
				sharedWith: {
					email: share.sharedWith.email,
					name: share.sharedWith.name
				},
				createdAt: share.createdAt,
				expiresAt: share.expiresAt
			}))
		});
	} catch (error: any) {
		console.error('Get outgoing shares error:', error);
		return json({ error: error.message || 'Failed to get shares' }, { status: 500 });
	}
};
