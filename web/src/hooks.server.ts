import { json } from '@sveltejs/kit';
import { ZodError } from 'zod';
import { auth } from '#lib/server/auth.ts';
import { svelteKitHandler } from 'better-auth/svelte-kit';
import { building } from '$app/env';
import { BETTER_AUTH_URL } from '$app/env/private';
import type { Handle, ServerInit } from '@sveltejs/kit/hooks';
import { migrate } from 'drizzle-orm/postgres-js/migrator';
import { db } from '#lib/server/db/index.ts';
import { and, eq, sql } from 'drizzle-orm';
import { encryptionDevice } from '#lib/server/db/schema.ts';

export const handle: Handle = async ({ event, resolve }) => {
	const path = event.url.pathname;
	if (
		path.startsWith('/api/') &&
		!path.startsWith('/api/auth/') &&
		!['GET', 'HEAD'].includes(event.request.method)
	) {
		const origin = event.request.headers.get('origin');
		const expectedOrigin = BETTER_AUTH_URL ? new URL(BETTER_AUTH_URL).origin : event.url.origin;
		if (origin && origin !== expectedOrigin)
			return json({ message: 'Invalid origin' }, { status: 403 });
		if (!event.request.headers.get('content-type')?.startsWith('application/json'))
			return json({ message: 'JSON required' }, { status: 415 });
		if (Number(event.request.headers.get('content-length')) > 16_000_000)
			return json({ message: 'Request too large' }, { status: 413 });
	}
	const session = await auth.api.getSession({
		headers: event.request.headers
	});
	if (session) {
		event.locals.session = session.session;
		event.locals.user = session.user;
	}
	try {
		const response = await svelteKitHandler({ event, resolve, auth, building });
		if (
			response.ok &&
			path.startsWith('/api/') &&
			!path.startsWith('/api/auth/') &&
			event.request.headers.has('authorization') &&
			event.locals.session
		) {
			await db
				.update(encryptionDevice)
				.set({ lastUsedAt: sql`now()` })
				.where(
					and(
						eq(encryptionDevice.sessionId, event.locals.session.id),
						eq(encryptionDevice.revoked, false)
					)
				);
		}
		if (path.startsWith('/api/') || path.startsWith('/dashboard'))
			response.headers.set('Cache-Control', 'no-store');
		return response;
	} catch (cause) {
		if (cause instanceof ZodError)
			return json({ message: 'Invalid request data' }, { status: 400 });
		throw cause;
	}
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
