import { json } from '@sveltejs/kit';
import { auth } from '$lib/server/auth';
import { getVaultEnv } from '$lib/server/env-vault';
import type { RequestHandler } from './$types';

export const GET: RequestHandler = async ({ request, url }) => {
	// Get session using bearer token from Authorization header
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

		// Get all environment variables for this vault path
		const envs = await getVaultEnv(userId, vaultPath);

		return json({
			success: true,
			message: `Retrieved ${Object.keys(envs).length} environment variable(s)`,
			envs
		});
	} catch (error: any) {
		return json({ error: error.message || 'Internal server error' }, { status: 500 });
	}
};
