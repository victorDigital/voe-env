import { json } from '@sveltejs/kit';
import { auth } from '$lib/server/auth';
import { getUserPublicKey, setUserPublicKey, getUserByEmail } from '$lib/server/shares';
import type { RequestHandler } from '@sveltejs/kit';

// GET - Get current user's public key or another user's public key by email
export const GET: RequestHandler = async ({ request, url }) => {
	const session = await auth.api.getSession({
		headers: request.headers
	});

	if (!session || !session.user) {
		return json({ error: 'Unauthorized' }, { status: 401 });
	}

	try {
		const email = url.searchParams.get('email');
		
		if (email) {
			// Get another user's public key (for sharing)
			const user = await getUserByEmail(email);
			if (!user) {
				return json({ error: 'User not found' }, { status: 404 });
			}
			if (!user.publicKey) {
				return json({ error: 'User has not set up encryption keys' }, { status: 404 });
			}
			return json({
				success: true,
				email: user.email,
				publicKey: user.publicKey
			});
		}

		// Get current user's public key
		const publicKey = await getUserPublicKey(session.user.id);
		return json({
			success: true,
			hasKey: !!publicKey,
			publicKey
		});
	} catch (error: any) {
		console.error('Get public key error:', error);
		return json({ error: error.message || 'Failed to get public key' }, { status: 500 });
	}
};

// POST - Set current user's public key
export const POST: RequestHandler = async ({ request }) => {
	const session = await auth.api.getSession({
		headers: request.headers
	});

	if (!session || !session.user) {
		return json({ error: 'Unauthorized' }, { status: 401 });
	}

	try {
		const body = await request.json();
		const { publicKey } = body;

		if (!publicKey || typeof publicKey !== 'string') {
			return json({ error: 'publicKey is required' }, { status: 400 });
		}

		// Validate that it looks like a valid public key (base64 encoded)
		try {
			const decoded = atob(publicKey);
			if (decoded.length < 32) {
				throw new Error('Key too short');
			}
		} catch {
			return json({ error: 'Invalid public key format' }, { status: 400 });
		}

		const success = await setUserPublicKey(session.user.id, publicKey);
		if (!success) {
			return json({ error: 'Failed to save public key' }, { status: 500 });
		}

		return json({
			success: true,
			message: 'Public key saved successfully'
		});
	} catch (error: any) {
		console.error('Set public key error:', error);
		return json({ error: error.message || 'Failed to set public key' }, { status: 500 });
	}
};
