import { betterAuth, type BetterAuthPlugin } from 'better-auth';
import { drizzleAdapter } from 'better-auth/adapters/drizzle';
import { sveltekitCookies } from 'better-auth/svelte-kit';
import { getRequestEvent } from '$app/server';
import { deviceAuthorization, bearer, organization, magicLink } from 'better-auth/plugins';
import { passkey } from '@better-auth/passkey';
import { APIError, createAuthMiddleware, isAPIError, getSessionFromCtx } from 'better-auth/api';
import { and, eq } from 'drizzle-orm';
import { BETTER_AUTH_URL, BETTER_AUTH_SECRET } from '$app/env/private';
import { building } from '$app/env';
import { db } from './db';
import {
	encryptionIdentity,
	organizationEnvelope,
	workspace,
	passkey as passkeyTable,
	passkeyVerification,
	encryptionDevice,
	deviceCode,
	session as sessionTable
} from './db/schema';
import { ac, roles } from '../permissions';
import { sendEmail } from './email';
import { recentlyVerified } from './recent-verification';
const baseURL = BETTER_AUTH_URL || 'http://localhost:5173';
const guardedPaths = new Set([
	'/organization/remove-member',
	'/organization/update-member-role',
	'/organization/leave',
	'/organization/delete',
	'/organization/add-member'
]);
const securityPlugin = (): BetterAuthPlugin => ({
	id: 'vault-security',
	hooks: {
		before: [
			{
				matcher: () => true,
				handler: createAuthMiddleware(async (ctx) => {
					if (guardedPaths.has(ctx.path))
						throw new APIError('FORBIDDEN', {
							message: 'Use workspace settings to preserve encryption access and ownership.'
						});
					if (ctx.path === '/passkey/delete-passkey') {
						const [credential] = await db
							.select()
							.from(passkeyTable)
							.where(eq(passkeyTable.id, String(ctx.body?.id || '')));
						Object.assign(ctx.context, { deletedCredential: credential?.credentialID });
					}
					if (ctx.path === '/organization/invite-member') {
						const session = await getSessionFromCtx(ctx);
						const orgId = String(
							ctx.body?.organizationId || session?.session.activeOrganizationId || ''
						);
						const [state] = await db
							.select()
							.from(workspace)
							.where(eq(workspace.organizationId, orgId));
						if (state && session) {
							const [own] = await db
								.select()
								.from(organizationEnvelope)
								.where(
									and(
										eq(organizationEnvelope.organizationId, orgId),
										eq(organizationEnvelope.recipient, `user:${session.user.id}`)
									)
								);
							if (!own || own.epoch !== state.epoch)
								throw new APIError('FORBIDDEN', {
									message: 'Your encryption identity must be approved before inviting members.'
								});
						}
					}
					if (ctx.path === '/device/token') {
						const [pending] = await db
							.select({ id: encryptionDevice.id })
							.from(encryptionDevice)
							.innerJoin(deviceCode, eq(deviceCode.id, encryptionDevice.deviceCodeId))
							.where(eq(deviceCode.deviceCode, String(ctx.body?.device_code || '')));
						if (!pending)
							throw new APIError('FORBIDDEN', { message: 'Enroll your CLI encryption key first.' });
						Object.assign(ctx.context, { vaultDeviceId: pending.id });
					}
					if (ctx.path === '/device/approve') {
						const code = String(ctx.body?.userCode || '')
							.replace(/[^a-zA-Z0-9]/g, '')
							.toUpperCase();
						const [enrollment] = await db
							.select()
							.from(encryptionDevice)
							.innerJoin(deviceCode, eq(encryptionDevice.deviceCodeId, deviceCode.id))
							.where(eq(deviceCode.userCode, code));
						if (!enrollment?.encryption_device.userId)
							throw new APIError('FORBIDDEN', { message: 'Approve encryption access first.' });
					}
					if (
						[
							'/passkey/generate-register-options',
							'/passkey/delete-passkey',
							'/organization/create',
							'/organization/invite-member'
						].includes(ctx.path)
					) {
						const s = await getSessionFromCtx(ctx);
						if (!s?.user.emailVerified)
							throw new APIError('FORBIDDEN', { message: 'Verify your email first.' });
						const [identity] = await db
							.select()
							.from(encryptionIdentity)
							.where(eq(encryptionIdentity.userId, s.user.id));
						if (identity && !(await recentlyVerified(s.session.id, s.user.id)))
							throw new APIError('FORBIDDEN', {
								message: 'Unlock with an enrolled passkey or recovery key first.'
							});
					}
				})
			}
		],
		after: [
			{
				matcher: (ctx) => !isAPIError(ctx.context.returned),
				handler: createAuthMiddleware(async (ctx) => {
					if (ctx.path === '/passkey/delete-passkey') {
						const credential = (ctx.context as typeof ctx.context & { deletedCredential?: string })
							.deletedCredential;
						if (credential) {
							const proofs = await db
								.select()
								.from(passkeyVerification)
								.where(eq(passkeyVerification.credentialId, credential));
							for (const proof of proofs)
								await db.delete(sessionTable).where(eq(sessionTable.id, proof.sessionId));
						}
					}
					if (ctx.path === '/passkey/generate-authenticate-options')
						return ctx.json({ ...(ctx.context.returned as object), userVerification: 'required' });
					if (ctx.path === '/passkey/verify-authentication') {
						const s = ctx.context.newSession;
						if (s)
							await db
								.insert(passkeyVerification)
								.values({ sessionId: s.session.id, credentialId: ctx.body.response.id })
								.onConflictDoUpdate({
									target: passkeyVerification.sessionId,
									set: {
										verifiedAt: new Date(),
										credentialId: ctx.body.response.id,
										recovery: false
									}
								});
					}
					if (ctx.path === '/passkey/verify-registration') {
						const s = await getSessionFromCtx(ctx);
						if (s) {
							const [identity] = await db
								.select()
								.from(encryptionIdentity)
								.where(eq(encryptionIdentity.userId, s.user.id));
							if (!identity)
								await db
									.insert(passkeyVerification)
									.values({ sessionId: s.session.id, credentialId: ctx.body.response.id })
									.onConflictDoUpdate({
										target: passkeyVerification.sessionId,
										set: { verifiedAt: new Date(), credentialId: ctx.body.response.id }
									});
						}
					}
					if (ctx.path === '/device/token') {
						const s = ctx.context.newSession;
						const deviceId = (ctx.context as typeof ctx.context & { vaultDeviceId?: string })
							.vaultDeviceId;
						if (s && deviceId)
							await db
								.update(encryptionDevice)
								.set({ sessionId: s.session.id })
								.where(
									and(eq(encryptionDevice.id, deviceId), eq(encryptionDevice.userId, s.user.id))
								);
					}
				})
			}
		]
	}
});
export const auth = betterAuth({
	database: drizzleAdapter(db, { provider: 'pg', transaction: true }),
	baseURL,
	secret: building ? crypto.randomUUID() : BETTER_AUTH_SECRET,
	emailAndPassword: { enabled: false },
	trustedOrigins: [new URL(baseURL).origin],
	plugins: [
		organization({
			ac,
			roles,
			requireEmailVerificationOnInvitation: true,
			sendInvitationEmail: async (data) => {
				await sendEmail(
					data.email,
					`Join ${data.organization.name} on VOE`,
					`You have been invited to ${data.organization.name}. Sign in with this email and accept at ${baseURL}/invite/${data.id}`
				);
			}
		}),
		passkey({
			rpID: new URL(baseURL).hostname,
			rpName: 'VOE',
			origin: new URL(baseURL).origin,
			authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
			registration: {
				afterVerification: async ({ verification }) => {
					if (!verification.registrationInfo?.userVerified)
						throw new APIError('FORBIDDEN', { message: 'Passkey user verification is required.' });
				}
			},
			authentication: {
				afterVerification: async ({ verification }) => {
					if (!verification.authenticationInfo.userVerified)
						throw new APIError('FORBIDDEN', { message: 'Passkey user verification is required.' });
				}
			}
		}),
		magicLink({
			expiresIn: 600,
			storeToken: 'hashed',
			sendMagicLink: async ({ email, url }) => {
				await sendEmail(
					email,
					'Your VOE sign-in link',
					`Sign in to VOE: ${url}\nThis link expires in 10 minutes. Your encryption recovery key is still required to recover an existing vault.`
				);
			}
		}),
		deviceAuthorization({
			verificationUri: '/device',
			validateClient: (clientId) => clientId === 'voe-cli'
		}),
		bearer(),
		securityPlugin(),
		sveltekitCookies(getRequestEvent)
	]
});
