import { redirect } from '@sveltejs/kit';
import { getRedirectTo } from '#lib/server/auth-pages.ts';
import type { PageServerLoad } from './$types';

export const load: PageServerLoad = ({ locals, url }) => {
	if (url.searchParams.has('redirectTo')) {
		const redirectTo = getRedirectTo(url);
		redirect(
			303,
			locals.user && locals.session
				? redirectTo
				: `/login?redirectTo=${encodeURIComponent(redirectTo)}`
		);
	}
	return { signedIn: !!(locals.user && locals.session) };
};
