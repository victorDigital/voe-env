import { json } from '@sveltejs/kit';
import { auth } from '$lib/server/auth';
import { setEnv } from '$lib/server/env-vault';
import type { RequestHandler } from './$types';

export const POST: RequestHandler = async ({ request }) => {
	// Get session using bearer token from Authorization header
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
				await setEnv(userId, fullKey, encryptedValue as string);
				successCount++;
			} catch (error: any) {
				errors.push(`Failed to set ${key}: ${error.message}`);
			}
		}

		return json({
			success: true,
			message: `Successfully uploaded ${successCount} environment variable(s)`,
			successCount,
			errorCount: errors.length,
			errors: errors.length > 0 ? errors : undefined
		});
	} catch (error: any) {
		return json({ error: error.message || 'Invalid request' }, { status: 400 });
	}
};
