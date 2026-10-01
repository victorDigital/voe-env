import { redirect } from '@sveltejs/kit';
import type { PageServerLoad } from './$types';

export const load: PageServerLoad = async ({ locals, url }) => {
	const requestedRedirect = url.searchParams.get('redirectTo') || '';
	const redirectTo =
		requestedRedirect.startsWith('/') &&
		!requestedRedirect.startsWith('//') &&
		!requestedRedirect.includes('\\') &&
		new URL(requestedRedirect, url).pathname !== '/'
			? requestedRedirect
			: '/dashboard';

	if (locals.user && locals.session) {
		throw redirect(303, redirectTo);
	}

	return { redirectTo };
};
