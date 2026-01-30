import { json } from '@sveltejs/kit';
import { auth } from '$lib/server/auth';
import { deleteShare } from '$lib/server/shares';
import type { RequestHandler } from './$types';

export const DELETE: RequestHandler = async ({ request, params }) => {
	const session = await auth.api.getSession({
		headers: request.headers
	});

	if (!session || !session.user) {
		return json({ error: 'Unauthorized' }, { status: 401 });
	}

	const shareId = params.id;
	if (!shareId) {
		return json({ error: 'Share ID is required' }, { status: 400 });
	}

	try {
		const deleted = await deleteShare(shareId, session.user.id);

		if (!deleted) {
			return json(
				{ error: 'Share not found or you do not have permission to delete it' },
				{ status: 404 }
			);
		}

		return json({
			success: true,
			message: 'Share revoked successfully'
		});
	} catch (error: any) {
		console.error('Delete share error:', error);
		return json({ error: error.message || 'Failed to revoke share' }, { status: 500 });
	}
};
