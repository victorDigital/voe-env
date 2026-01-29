import { auth } from '$lib/server/auth';
import { svelteKitHandler } from 'better-auth/svelte-kit';
import { building, dev } from '$app/environment';
import type { Handle } from '@sveltejs/kit';
import type { ServerInit } from '@sveltejs/kit';
import { drizzle } from 'drizzle-orm/bun-sqlite';
import { migrate } from 'drizzle-orm/bun-sqlite/migrator';
import { Database } from 'bun:sqlite';
import { DATABASE_URL } from '$env/static/private';
import * as schema from '$lib/server/db/schema';
import path from 'path';

export const handle: Handle = async ({ event, resolve }) => {
	// Fetch current session from Better Auth
	const session = await auth.api.getSession({
		headers: event.request.headers
	});
	// Make session and user available on server
	if (session) {
		event.locals.session = session.session;
		event.locals.user = session.user;
	}
	return svelteKitHandler({ event, resolve, auth, building });
};

export const init: ServerInit = async () => {
	// Run migrations in both dev and production
	// In dev, we want to ensure the database is up to date
	// In production, this is critical
	console.log('[INIT] Running database initialization...');
	console.log('[INIT] Environment - dev:', dev, 'NODE_ENV:', process.env.NODE_ENV);
	console.log('[INIT] DATABASE_URL:', DATABASE_URL);

	try {
		// Parse database URL to get actual path
		const dbPath = DATABASE_URL.startsWith('file:') ? DATABASE_URL.substring(5) : DATABASE_URL;

		console.log('[INIT] Database path:', dbPath);

		// Create database connection
		const client = new Database(dbPath, { create: true });
		const db = drizzle(client, { schema });

		// Determine migrations folder path
		// In production (Docker), migrations are at /app/drizzle
		// In development, they're at ./drizzle relative to project root
		const migrationsFolder = dev ? './drizzle' : '/app/drizzle';

		console.log('[INIT] Migrations folder:', migrationsFolder);

		// Run migrations
		await migrate(db, { migrationsFolder });

		console.log('[INIT] ✓ Migrations completed successfully');

		// Close this connection as the app will create its own
		client.close();
	} catch (error) {
		console.error('[INIT] ✗ Migration failed:', error);
		throw error;
	}
};
