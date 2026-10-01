import { betterAuth } from 'better-auth';
import { drizzleAdapter } from 'better-auth/adapters/drizzle';
import { db } from './db';
import { sveltekitCookies } from 'better-auth/svelte-kit';
import { getRequestEvent } from '$app/server';
import { deviceAuthorization, bearer } from 'better-auth/plugins';
import { createAuthMiddleware } from 'better-auth/plugins';
import { deviceLog, deviceCode } from './db/schema';
import { eq } from 'drizzle-orm';
import type { BetterAuthPlugin } from 'better-auth';
import { BETTER_AUTH_URL } from '$env/static/private';
import { env } from '$env/dynamic/private';

const deviceLogPlugin = (): BetterAuthPlugin => ({
	id: 'device-log',
	hooks: {
		after: [
			{
				matcher: (context) => context.path === '/api/auth/device/approve',
				handler: createAuthMiddleware(async (ctx) => {
					const userCode = (ctx as any).body?.userCode;
					if (userCode) {
						const deviceCodeEntry = await db
							.select()
							.from(deviceCode)
							.where(eq(deviceCode.userCode, userCode))
							.limit(1);
						if (deviceCodeEntry.length > 0) {
							const { userId, clientId, scope } = deviceCodeEntry[0];
							const insertData: any = {
								id: crypto.randomUUID(),
								userId,
								clientId: clientId || 'voe-cli',
								userCode,
								approvedAt: new Date().toISOString()
							};
							if (scope) {
								insertData.scope = scope;
							}
							await db.insert(deviceLog).values(insertData);
						}
					}
					return ctx;
				})
			}
		]
	}
});

export const auth = betterAuth({
	database: drizzleAdapter(db, {
		provider: 'pg'
	}),
	baseURL: BETTER_AUTH_URL,
	secret: env.BETTER_AUTH_SECRET,
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
