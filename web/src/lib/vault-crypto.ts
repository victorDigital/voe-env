import { context } from './vault-format';
export const bytes = (s: string) => new TextEncoder().encode(s);
export function encode(value: Uint8Array | ArrayBuffer): string {
	return btoa(
		Array.from(new Uint8Array(value instanceof Uint8Array ? value : value), (v) =>
			String.fromCharCode(v)
		).join('')
	);
}
export const decode = (value: string): Uint8Array<ArrayBuffer> =>
	Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
export const randomKey = () => crypto.getRandomValues(new Uint8Array(32));
export async function seal(
	key: Uint8Array<ArrayBuffer>,
	value: Uint8Array<ArrayBuffer>,
	aad: string
): Promise<string> {
	const nonce = crypto.getRandomValues(new Uint8Array(12));
	const imported = await crypto.subtle.importKey('raw', key, 'AES-GCM', false, ['encrypt']);
	const ciphertext = await crypto.subtle.encrypt(
		{ name: 'AES-GCM', iv: nonce, additionalData: bytes(aad) },
		imported,
		value
	);
	return 'v1.' + encode(new Uint8Array([...nonce, ...new Uint8Array(ciphertext)]));
}
export async function unseal(
	key: Uint8Array<ArrayBuffer>,
	envelope: string,
	aad: string
): Promise<Uint8Array<ArrayBuffer>> {
	if (!envelope.startsWith('v1.')) throw new Error('Unsupported encryption format');
	const data = decode(envelope.slice(3));
	if (data.length < 28) throw new Error('Invalid ciphertext');
	const imported = await crypto.subtle.importKey('raw', key, 'AES-GCM', false, ['decrypt']);
	return new Uint8Array(
		await crypto.subtle.decrypt(
			{ name: 'AES-GCM', iv: data.slice(0, 12), additionalData: bytes(aad) },
			imported,
			data.slice(12)
		)
	);
}
export async function derivePrf(output: Uint8Array<ArrayBuffer>, userId: string) {
	const key = await crypto.subtle.importKey('raw', output, 'HKDF', false, ['deriveBits']);
	return new Uint8Array(
		await crypto.subtle.deriveBits(
			{
				name: 'HKDF',
				hash: 'SHA-256',
				salt: bytes('voe-prf-v1'),
				info: bytes(context('account', userId))
			},
			key,
			256
		)
	);
}
export async function identityKeyPair() {
	const pair = await crypto.subtle.generateKey(
		{
			name: 'RSA-OAEP',
			modulusLength: 3072,
			publicExponent: new Uint8Array([1, 0, 1]),
			hash: 'SHA-256'
		},
		true,
		['encrypt', 'decrypt']
	);
	return {
		publicKey: encode(await crypto.subtle.exportKey('spki', pair.publicKey)),
		privateKey: new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey))
	};
}
export async function wrapTo(publicKey: string, key: Uint8Array<ArrayBuffer>, aad: string) {
	const imported = await crypto.subtle.importKey(
		'spki',
		decode(publicKey),
		{ name: 'RSA-OAEP', hash: 'SHA-256' },
		false,
		['encrypt']
	);
	return (
		'rsa1.' +
		encode(await crypto.subtle.encrypt({ name: 'RSA-OAEP', label: bytes(aad) }, imported, key))
	);
}
export async function unwrapFrom(
	privateKey: Uint8Array<ArrayBuffer>,
	envelope: string,
	aad: string
) {
	if (!envelope.startsWith('rsa1.')) throw new Error('Unsupported key envelope');
	const imported = await crypto.subtle.importKey(
		'pkcs8',
		privateKey,
		{ name: 'RSA-OAEP', hash: 'SHA-256' },
		false,
		['decrypt']
	);
	return new Uint8Array(
		await crypto.subtle.decrypt(
			{ name: 'RSA-OAEP', label: bytes(aad) },
			imported,
			decode(envelope.slice(5))
		)
	);
}
export async function fingerprint(publicKey: string) {
	return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', decode(publicKey))), (b) =>
		b.toString(16).padStart(2, '0')
	).join('');
}
