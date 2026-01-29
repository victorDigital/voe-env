import { betterAuth } from 'better-auth';
import { drizzleAdapter } from 'better-auth/adapters/drizzle';
import { db } from './db';
import { sveltekitCookies } from 'better-auth/svelte-kit';
import { getRequestEvent } from '$app/server';
import { genericOAuth, deviceAuthorization, bearer } from 'better-auth/plugins';
import { createAuthMiddleware } from 'better-auth/plugins';
import { deviceLog, deviceCode } from './db/schema';
import { eq } from 'drizzle-orm';
import type { BetterAuthPlugin } from 'better-auth';

// Use process.env for runtime environment variable access
const BETTER_AUTH_URL = process.env.BETTER_AUTH_URL || 'http://localhost:5173';
const VOE_AUTH_CLIENT_ID = process.env.VOE_AUTH_CLIENT_ID || '';
const VOE_AUTH_CLIENT_SECRET = process.env.VOE_AUTH_CLIENT_SECRET || '';

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
	baseUrl: BETTER_AUTH_URL,
	plugins: [
		genericOAuth({
			config: [
				{
					providerId: 'voe-auth',
					clientId: VOE_AUTH_CLIENT_ID,
					pkce: true,
					clientSecret: VOE_AUTH_CLIENT_SECRET,
					discoveryUrl: 'https://auth.voe.dk/.well-known/openid-configuration'
				}
			]
		}),
		deviceAuthorization({
			verificationUri: '/device'
		}),
		bearer(),
		sveltekitCookies(getRequestEvent),
		deviceLogPlugin()
	]
});
