import { json } from '@sveltejs/kit';
import { auth } from '$lib/server/auth';
import type { RequestHandler } from './$types';

export const GET: RequestHandler = async ({ request }) => {
	// Get session using bearer token from Authorization header
	const session = await auth.api.getSession({
		headers: request.headers
	});

	if (!session || !session.user) {
		return json({ error: 'Unauthorized' }, { status: 401 });
	}

	// Return a success response with user info
	return json({
		success: true,
		message: 'Protected API endpoint accessed successfully',
		user: {
			id: session.user.id,
			name: session.user.name,
			email: session.user.email
		},
		timestamp: new Date().toISOString()
	});
};
