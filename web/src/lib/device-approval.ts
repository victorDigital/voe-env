import { fingerprint } from './vault-crypto';

function normalizeFingerprint(value: string) {
	const normalized = value.replace(/\s/g, '').toLowerCase();
	return /^[a-f0-9]{64}$/.test(normalized) ? normalized : '';
}

export function readDeviceFingerprint(params: URLSearchParams) {
	const supplied = params.getAll('fingerprint');
	if (!supplied.length) return { deviceFingerprint: '', fingerprintError: '' };
	const deviceFingerprint = supplied.length === 1 ? normalizeFingerprint(supplied[0]) : '';
	return {
		deviceFingerprint,
		fingerprintError: deviceFingerprint
			? ''
			: 'This link has an invalid device fingerprint. Paste the full fingerprint from your terminal or run ve auth again.'
	};
}

export async function verifyDeviceFingerprint(value: string, publicKey: string) {
	const expected = normalizeFingerprint(value);
	if (!expected) throw new Error('Paste the full device fingerprint printed by ve auth.');
	if (expected !== (await fingerprint(publicKey))) {
		throw new Error(
			'The fingerprint does not match this device. Run ve auth again and open the new link.'
		);
	}
}
