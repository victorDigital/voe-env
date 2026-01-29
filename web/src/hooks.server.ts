import { auth } from '$lib/server/auth';
import { svelteKitHandler } from 'better-auth/svelte-kit';
import { building, dev } from '$app/environment';
import type { Handle } from '@sveltejs/kit';
import type { ServerInit } from '@sveltejs/kit';
import { drizzle } from 'drizzle-orm/postgres-js';
import { migrate } from 'drizzle-orm/postgres-js/migrator';
import postgres from 'postgres';
import * as schema from '$lib/server/db/schema';

const DATABASE_URL = process.env.DATABASE_URL;

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
	console.log('[INIT] Running database initialization...');
	console.log('[INIT] Environment - dev:', dev, 'NODE_ENV:', process.env.NODE_ENV);

	if (!DATABASE_URL) {
		console.error('[INIT] ✗ DATABASE_URL environment variable is required');
		throw new Error('DATABASE_URL environment variable is required');
	}

	try {
		console.log('[INIT] Connecting to PostgreSQL...');

		const db = drizzle({ connection: DATABASE_URL });

		// Determine migrations folder path
		const migrationsFolder = dev ? './drizzle' : '/app/drizzle';
		console.log('[INIT] Migrations folder:', migrationsFolder);

		// Run migrations
		await migrate(db, { migrationsFolder });

		console.log('[INIT] ✓ Migrations completed successfully');
	} catch (error) {
		console.error('[INIT] ✗ Migration failed:', error);
		throw error;
	}
};
