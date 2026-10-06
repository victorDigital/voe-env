import { describe, expect, test } from 'bun:test';
import { getRedirectTo, loadAuthPage } from '../src/lib/server/auth-pages';
import { readDeviceFingerprint, verifyDeviceFingerprint } from '../src/lib/device-approval';
import { encode, fingerprint } from '../src/lib/vault-crypto';
import { isRedirect, type RequestEvent } from '@sveltejs/kit';

describe('device fingerprint links', () => {
	const expected = '0123456789abcdef'.repeat(4);

	test('prefills the full fingerprint supplied by the CLI', () => {
		const params = new URLSearchParams({ user_code: 'ABCD-EFGH', fingerprint: expected });
		expect(readDeviceFingerprint(params)).toEqual({
			deviceFingerprint: expected,
			fingerprintError: ''
		});
	});

	test('keeps manual entry available when no fingerprint was supplied', () => {
		expect(readDeviceFingerprint(new URLSearchParams('user_code=ABCD-EFGH'))).toEqual({
			deviceFingerprint: '',
			fingerprintError: ''
		});
	});

	test.each(['', expected.slice(0, -1), expected + '0', 'z'.repeat(64)])(
		'rejects malformed fingerprint %p without prefilling it',
		(value) => {
			const result = readDeviceFingerprint(new URLSearchParams({ fingerprint: value }));
			expect(result.deviceFingerprint).toBe('');
			expect(result.fingerprintError).toContain('Paste the full fingerprint from your terminal');
		}
	);

	test('rejects ambiguous duplicate fingerprints', () => {
		const params = new URLSearchParams({ fingerprint: expected });
		params.append('fingerprint', expected);
		expect(readDeviceFingerprint(params).fingerprintError).not.toBe('');
	});

	test('retains the CLI fingerprint through login for signed out and signed in users', () => {
		const destination = `/device?user_code=ABCD-EFGH&fingerprint=${expected}`;
		const login = new URL('https://env.voe.dk/login');
		login.searchParams.set('redirectTo', destination);
		expect(getRedirectTo(login)).toBe(destination);
		expect(loadAuthPage({ url: login, locals: {} } as RequestEvent)).toEqual({
			redirectTo: destination
		});
		let redirect: unknown;
		try {
			loadAuthPage({
				url: login,
				locals: { user: { id: 'user' }, session: { id: 'session' } }
			} as RequestEvent);
		} catch (error) {
			redirect = error;
		}
		expect(isRedirect(redirect)).toBe(true);
		if (isRedirect(redirect)) expect(redirect.location).toBe(destination);
	});
});

describe('device key verification', () => {
	const enrolledKey = encode(new Uint8Array([1, 2, 3]));
	const substitutedKey = encode(new Uint8Array([4, 5, 6]));

	test('accepts only the public key bound to the CLI-supplied fingerprint', async () => {
		const expected = await fingerprint(enrolledKey);
		await expect(verifyDeviceFingerprint(expected, enrolledKey)).resolves.toBeUndefined();
		await expect(verifyDeviceFingerprint(expected, substitutedKey)).rejects.toThrow(
			'The fingerprint does not match this device'
		);
	});

	test('accepts a manually pasted uppercase fingerprint with whitespace', async () => {
		const expected = await fingerprint(enrolledKey);
		const pasted = expected.toUpperCase().match(/.{8}/g)!.join(' ');
		await expect(verifyDeviceFingerprint(`\n${pasted}\n`, enrolledKey)).resolves.toBeUndefined();
	});

	test('never accepts an omitted or partial fingerprint', async () => {
		const expected = await fingerprint(enrolledKey);
		for (const input of ['', expected.slice(0, 12)]) {
			await expect(verifyDeviceFingerprint(input, enrolledKey)).rejects.toThrow(
				'Paste the full device fingerprint'
			);
		}
	});
});
