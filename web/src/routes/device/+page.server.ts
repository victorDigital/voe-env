import { redirect } from '@sveltejs/kit';
import type { PageServerLoad } from './$types';

export const load: PageServerLoad = async ({ locals, url }) => {
	// Require authentication for device authorization
	if (!locals.user || !locals.session) {
		throw redirect(302, '/');
	}

	return {
		user: locals.user,
		userCode: url.searchParams.get('user_code') || ''
	};
};
