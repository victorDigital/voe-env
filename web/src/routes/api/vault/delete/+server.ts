import { json } from '@sveltejs/kit';
import { auth } from '$lib/server/auth';
import { deleteEnv } from '$lib/server/env-vault';
import type { RequestHandler } from './$types';

export const DELETE: RequestHandler = async ({ request }) => {
	// Get session using bearer token from Authorization header
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
				await deleteEnv(userId, fullKey);
				deletedCount++;
			} catch (error: any) {
				errors.push(`Failed to delete ${key}: ${error.message}`);
			}
		}

		return json({
			success: true,
			message: `Successfully deleted ${deletedCount} environment variable(s)`,
			deletedCount,
			errorCount: errors.length,
			errors: errors.length > 0 ? errors : undefined
		});
	} catch (error: any) {
		return json({ error: error.message || 'Invalid request' }, { status: 400 });
	}
};
