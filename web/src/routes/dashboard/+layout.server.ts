import { redirect } from '@sveltejs/kit';
import type { LayoutServerLoad } from './$types';

export const load: LayoutServerLoad = ({ locals, url, cookies }) => {
	if (!locals.user || !locals.session) {
		redirect(303, `/login?redirectTo=${encodeURIComponent(url.pathname + url.search)}`);
	}

	return {
		user: locals.user,
		sidebarOpen: cookies.get('sidebar_state') !== 'false'
	};
};
