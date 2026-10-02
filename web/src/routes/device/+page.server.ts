import { redirect } from '@sveltejs/kit';
import { isAPIError } from 'better-auth/api';
import { auth } from '#lib/server/auth.ts';
import type { PageServerLoad } from './$types';

export const load: PageServerLoad = async ({ locals, request, url }) => {
	if (!locals.user || !locals.session) {
		redirect(303, `/login?redirectTo=${encodeURIComponent(url.pathname + url.search)}`);
	}

	const userCode = (url.searchParams.get('user_code') || '')
		.trim()
		.replace(/[\s-]/g, '')
		.toUpperCase();
	let verificationError = '';

	if (userCode) {
		try {
			const verification = await auth.api.deviceVerify({
				query: { user_code: userCode },
				headers: request.headers
			});
			if (verification.status !== 'pending') {
				verificationError = 'This code has already been used. Run ve auth again.';
			} else if (!verification.client_id) {
				verificationError = 'This code belongs to another account.';
			}
		} catch (error) {
			verificationError =
				isAPIError(error) && typeof error.body?.error_description === 'string'
					? error.body.error_description
					: 'Could not verify this code. Try again.';
		}
	}

	return { user: locals.user, userCode, verificationError };
};
