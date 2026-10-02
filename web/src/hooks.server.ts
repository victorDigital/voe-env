import { auth } from '#lib/server/auth.ts';
import { svelteKitHandler } from 'better-auth/svelte-kit';
import { building } from '$app/env';
import type { Handle, ServerInit } from '@sveltejs/kit/hooks';
import { migrate } from 'drizzle-orm/postgres-js/migrator';
import { db } from '#lib/server/db/index.ts';

export const handle: Handle = async ({ event, resolve }) => {
	const session = await auth.api.getSession({
		headers: event.request.headers
	});
	if (session) {
		event.locals.session = session.session;
		event.locals.user = session.user;
	}
	return svelteKitHandler({ event, resolve, auth, building });
};

export const init: ServerInit = async () => {
	if (building) return;

	console.log('[INIT] Running database initialization...');

	try {
		await migrate(db, { migrationsFolder: './drizzle' });

		console.log('[INIT] ✓ Migrations completed successfully');
	} catch (error) {
		console.error('[INIT] ✗ Migration failed:', error);
		throw error;
	}
};
