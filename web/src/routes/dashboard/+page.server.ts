import { redirect } from '@sveltejs/kit';
import { eq } from 'drizzle-orm';
import { db } from '$lib/server/db';
import { deviceLog } from '$lib/server/db/schema';
import type { PageServerLoad } from './$types';

export const load: PageServerLoad = async ({ locals }) => {
	// Ensure user is authenticated
	if (!locals.user || !locals.session) {
		throw redirect(302, '/');
	}

	// Fetch authorized devices (logged approvals)
	const devices = await db
		.select({
			id: deviceLog.id,
			userCode: deviceLog.userCode,
			clientId: deviceLog.clientId,
			scope: deviceLog.scope,
			approvedAt: deviceLog.approvedAt
		})
		.from(deviceLog)
		.where(eq(deviceLog.userId, locals.user.id));

	return {
		session: locals.session || null,
		user: locals.user || null,
		devices
	};
};
