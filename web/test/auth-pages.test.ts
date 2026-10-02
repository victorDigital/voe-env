/// <reference types="bun" />

import { describe, expect, test } from 'bun:test';
import { isRedirect, type RequestEvent } from '@sveltejs/kit';
import { getRedirectTo, loadAuthPage } from '../src/lib/server/auth-pages.ts';

function authUrl(redirectTo?: string) {
	const url = new URL('https://env.voe.dk/login');
	if (redirectTo !== undefined) url.searchParams.set('redirectTo', redirectTo);
	return url;
}

describe('authentication return destination', () => {
	test.each([undefined, ''])('defaults to the dashboard for %p', (redirectTo) => {
		expect(getRedirectTo(authUrl(redirectTo))).toBe('/dashboard');
	});

	test.each([
		'/dashboard/env?path=team%3Aproduction',
		'/device?user_code=ABCD-EFGH&scope=read%20write#confirm'
	])('preserves the requested path, query, and fragment: %s', (redirectTo) => {
		expect(getRedirectTo(authUrl(redirectTo))).toBe(redirectTo);
	});

	test('resolves dot segments before selecting the destination', () => {
		expect(getRedirectTo(authUrl('/dashboard/../device?user_code=ABCD-EFGH'))).toBe(
			'/device?user_code=ABCD-EFGH'
		);
	});

	test.each([
		'https://example.com/device',
		'https://env.voe.dk/device',
		'//example.com/device',
		'///example.com/device',
		'/\\example.com/device',
		'/device\\authorization',
		'/\t/example.com/device',
		'device?user_code=ABCD-EFGH',
		'javascript:alert(1)'
	])('rejects a destination outside the local path contract: %s', (redirectTo) => {
		expect(getRedirectTo(authUrl(redirectTo))).toBe('/dashboard');
	});

	test.each([
		'/',
		'/?redirectTo=/device',
		'/login',
		'/login/?redirectTo=/device',
		'/signup',
		'/signup/?redirectTo=/device',
		'/device/../login?redirectTo=/device'
	])('prevents a return through an authentication entry point: %s', (redirectTo) => {
		expect(getRedirectTo(authUrl(redirectTo))).toBe('/dashboard');
	});
});

describe('authentication page loading', () => {
	test('retains a CLI authorization request while logged out', () => {
		const redirectTo = '/device?user_code=ABCD-EFGH';
		const event = { url: authUrl(redirectTo), locals: {} } as RequestEvent;
		expect(loadAuthPage(event)).toEqual({ redirectTo });
	});

	test.each([{ user: { id: 'user' } }, { session: { id: 'session' } }])(
		'requires both the user and session before redirecting',
		(locals) => {
			const event = {
				url: authUrl('/device?user_code=ABCD-EFGH'),
				locals
			} as unknown as RequestEvent;
			expect(loadAuthPage(event)).toEqual({ redirectTo: '/device?user_code=ABCD-EFGH' });
		}
	);

	test.each([
		['/device?user_code=ABCD-EFGH', '/device?user_code=ABCD-EFGH'],
		['//example.com/device', '/dashboard']
	])('redirects an existing session to the safe destination for %s', (requested, expected) => {
		const event = {
			url: authUrl(requested),
			locals: { user: { id: 'user' }, session: { id: 'session' } }
		} as RequestEvent;
		let result: unknown;
		try {
			loadAuthPage(event);
		} catch (error) {
			result = error;
		}
		expect(isRedirect(result)).toBe(true);
		if (isRedirect(result)) {
			expect(result.status).toBe(303);
			expect(result.location).toBe(expected);
		}
	});
});
