import type { BetterAuthPlugin } from 'better-auth';
import {
	APIError,
	createAuthEndpoint,
	formCsrfMiddleware,
	getSessionFromCtx
} from 'better-auth/api';
import { setSessionCookie } from 'better-auth/cookies';
import { revokeUnprovenAccountAccess } from 'better-auth/db';
import { z } from 'zod';
import { consumeInvitationProof, readInvitationProof } from './invitation-proof';

export const invitationAuth = () =>
	({
		id: 'invitation-auth',
		endpoints: {
			signInInvitation: createAuthEndpoint(
				'/sign-in/invitation',
				{
					method: 'POST',
					requireHeaders: true,
					use: [formCsrfMiddleware],
					body: z.object({
						invitationId: z.string().min(1).max(128),
						token: z.string().length(43),
						name: z.string().trim().max(100).optional()
					})
				},
				async (ctx) => {
					const invalid = () =>
						new APIError('BAD_REQUEST', {
							message:
								'This invitation link has expired or already been used. Ask for a new invitation.'
						});
					const invite = await readInvitationProof(ctx.body.invitationId, ctx.body.token);
					if (!invite) throw invalid();
					const email = invite.email.toLowerCase();
					const current = await getSessionFromCtx(ctx);
					if (current && current.user.email.toLowerCase() !== email)
						throw new APIError('FORBIDDEN', { message: `Sign out before joining as ${email}.` });
					let user = (await ctx.context.internalAdapter.findUserByEmail(email))?.user;
					if (!user && !ctx.body.name)
						throw new APIError('BAD_REQUEST', { message: 'Enter your name.' });
					if (!(await consumeInvitationProof(invite.id, ctx.body.token))) throw invalid();
					if (!user)
						user = await ctx.context.internalAdapter.createUser(
							{ email, name: ctx.body.name!, emailVerified: true },
							{ method: 'invitation' }
						);
					if (!user.emailVerified) {
						const verified = await revokeUnprovenAccountAccess(ctx, user.id);
						if (!verified) throw invalid();
						user = verified;
					}
					const session = await ctx.context.internalAdapter.createSession(user.id);
					if (!session)
						throw new APIError('INTERNAL_SERVER_ERROR', {
							message: 'Could not sign in. Please try signing in again.'
						});
					await setSessionCookie(ctx, { session, user });
					return ctx.json({ invitationId: invite.id });
				}
			)
		},
		rateLimit: [
			{ pathMatcher: (path: string) => path === '/sign-in/invitation', window: 60, max: 5 }
		]
	}) satisfies BetterAuthPlugin;
