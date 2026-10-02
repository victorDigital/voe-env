import { betterAuth } from 'better-auth';
import { drizzleAdapter } from 'better-auth/adapters/drizzle';
import { db } from './db';
import { sveltekitCookies } from 'better-auth/svelte-kit';
import { getRequestEvent } from '$app/server';
import { deviceAuthorization, bearer } from 'better-auth/plugins';
import { createAuthMiddleware, isAPIError } from 'better-auth/api';
import { deviceLog, deviceCode } from './db/schema';
import { and, eq, or } from 'drizzle-orm';
import type { BetterAuthPlugin } from 'better-auth';
import { BETTER_AUTH_URL, BETTER_AUTH_SECRET } from '$app/env/private';
import { building } from '$app/env';

const deviceLogPlugin = (): BetterAuthPlugin => ({
	id: 'device-log',
	hooks: {
		after: [
			{
				matcher: (context) =>
					context.path === '/device/approve' && !isAPIError(context.context.returned),
				handler: createAuthMiddleware(async (ctx) => {
					const userCode = ctx.body?.userCode;
					if (typeof userCode !== 'string') return;

					const normalizedCode = userCode.replace(/[^a-zA-Z0-9]/g, '').toUpperCase();
					const [approvedDevice] = await db
						.select()
						.from(deviceCode)
						.where(
							and(
								eq(deviceCode.status, 'approved'),
								or(eq(deviceCode.userCode, userCode), eq(deviceCode.userCode, normalizedCode))
							)
						)
						.limit(1);
					if (!approvedDevice?.userId) return;

					await db.insert(deviceLog).values({
						id: crypto.randomUUID(),
						userId: approvedDevice.userId,
						clientId: approvedDevice.clientId || 'voe-cli',
						userCode: approvedDevice.userCode,
						scope: approvedDevice.scope,
						approvedAt: new Date()
					});
				})
			}
		]
	}
});

export const auth = betterAuth({
	database: drizzleAdapter(db, {
		provider: 'pg'
	}),
	baseURL: BETTER_AUTH_URL || undefined,
	secret: building ? crypto.randomUUID() : BETTER_AUTH_SECRET,
	emailAndPassword: {
		enabled: true
	},
	trustedOrigins: ['http://localhost:5173', 'https://env.voe.dk'],
	plugins: [
		deviceAuthorization({
			verificationUri: '/device'
		}),
		bearer(),
		deviceLogPlugin(),
		sveltekitCookies(getRequestEvent)
	]
});
