import { redirect } from '@sveltejs/kit';
import { eq } from 'drizzle-orm';
import { auth } from '#lib/server/auth.ts';
import { db } from '#lib/server/db/index.ts';
import { user } from '#lib/server/db/schema.ts';
import { readInvitationProof } from '#lib/server/invitation-proof.ts';
import type { PageServerLoad } from './$types';

export const load: PageServerLoad = async ({ locals, url, params, request, setHeaders }) => {
	setHeaders({ 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer' });
	const token = url.searchParams.get('token');
	if (token) {
		const invitation = await readInvitationProof(params.id, token);
		if (!invitation) return { invitation: null, user: locals.user, token: null, needsName: false };
		const [existing] = await db
			.select({ id: user.id })
			.from(user)
			.where(eq(user.email, invitation.email.toLowerCase()));
		return { invitation, user: locals.user, token, needsName: !existing };
	}
	if (!locals.user) redirect(303, `/login?redirectTo=${encodeURIComponent(url.pathname)}`);
	const invitation = await auth.api.getInvitation({
		query: { id: params.id },
		headers: request.headers
	});
	return { invitation, user: locals.user, token: null, needsName: false };
};
