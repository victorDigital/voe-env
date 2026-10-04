import { redirect } from '@sveltejs/kit';
import { auth } from '#lib/server/auth.ts';
import type { PageServerLoad } from './$types';
export const load: PageServerLoad = async ({ locals, url, params, request }) => {
	if (!locals.user) redirect(303, `/login?redirectTo=${encodeURIComponent(url.pathname)}`);
	const invitation = await auth.api.getInvitation({
		query: { id: params.id },
		headers: request.headers
	});
	return { invitation, user: locals.user };
};
