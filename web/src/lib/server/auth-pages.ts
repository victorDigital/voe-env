import { redirect, type RequestEvent } from '@sveltejs/kit';

export function getRedirectTo(url: URL) {
	const value = url.searchParams.get('redirectTo') || '/dashboard';
	if (!value.startsWith('/') || value.startsWith('//') || value.includes('\\')) return '/dashboard';
	try {
		const target = new URL(value, url);
		if (
			target.origin !== url.origin ||
			['/', '/login', '/signup'].includes(target.pathname.replace(/\/$/, '') || '/')
		)
			return '/dashboard';
		return target.pathname + target.search + target.hash;
	} catch {
		return '/dashboard';
	}
}

export function loadAuthPage({ locals, url }: RequestEvent) {
	const redirectTo = getRedirectTo(url);
	if (locals.user && locals.session) redirect(303, redirectTo);
	return { redirectTo };
}
