import { auth } from '$lib/server/auth';
import { svelteKitHandler } from 'better-auth/svelte-kit';
import { building, dev } from '$app/environment';
import type { Handle } from '@sveltejs/kit';
import type { ServerInit } from '@sveltejs/kit';
import { drizzle } from 'drizzle-orm/bun-sqlite';
import { migrate } from 'drizzle-orm/bun-sqlite/migrator';

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
	if (!dev) {
		if (process.env.NODE_ENV === 'production') {
			if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL is not set');
			const db = drizzle(process.env.DATABASE_URL);
			migrate(db, { migrationsFolder: 'drizzle' });
			console.log('migrations complete');
		}
	}
};
