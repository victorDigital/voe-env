import { json } from '@sveltejs/kit';
import { auth } from '$lib/server/auth';
import { createShare, getUserByEmail, hasShareAccess } from '$lib/server/shares';
import { getVaultEnv } from '$lib/server/env-vault';
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
		const { folderPath, recipientEmail, permission = 'read', vaultPassword, expiresAt } = body;

		if (!folderPath || typeof folderPath !== 'string') {
			return json({ error: 'folderPath is required' }, { status: 400 });
		}

		if (!recipientEmail || typeof recipientEmail !== 'string') {
			return json({ error: 'recipientEmail is required' }, { status: 400 });
		}

		if (!vaultPassword || typeof vaultPassword !== 'string') {
			return json({ error: 'vaultPassword is required' }, { status: 400 });
		}

		if (!['read', 'readwrite'].includes(permission)) {
			return json({ error: 'permission must be "read" or "readwrite"' }, { status: 400 });
		}

		const ownerId = session.user.id;

		// Verify the owner actually has data at this path
		const ownerEnvVars = await getVaultEnv(ownerId, folderPath);
		if (Object.keys(ownerEnvVars).length === 0) {
			return json(
				{ error: 'You do not have any environment variables at this folder path' },
				{ status: 404 }
			);
		}

		// Find the recipient user
		const recipient = await getUserByEmail(recipientEmail);
		if (!recipient) {
			return json({ error: `User with email ${recipientEmail} not found` }, { status: 404 });
		}

		if (recipient.id === ownerId) {
			return json({ error: 'Cannot share with yourself' }, { status: 400 });
		}

		// Check if already shared
		const existingShare = await hasShareAccess(recipient.id, folderPath);
		if (existingShare.hasAccess) {
			return json(
				{ error: 'This folder is already shared with this user' },
				{ status: 409 }
			);
		}

		// Create the share
		const expiresDate = expiresAt ? new Date(expiresAt) : undefined;
		const share = await createShare(
			ownerId,
			recipient.id,
			folderPath,
			permission,
			vaultPassword,
			expiresDate
		);

		return json({
			success: true,
			message: `Folder ${folderPath} shared with ${recipientEmail} as ${permission}`,
			share: {
				id: share.id,
				folderPath: share.folderPath,
				permission: share.permission,
				recipientEmail: recipient.email,
				createdAt: share.createdAt,
				expiresAt: share.expiresAt
			}
		});
	} catch (error: any) {
		console.error('Share creation error:', error);
		return json({ error: error.message || 'Failed to create share' }, { status: 500 });
	}
};
