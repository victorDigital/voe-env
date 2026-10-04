import { decode } from './vault-crypto';
export function getStoredPrivateKey(): string | null {
	return localStorage.getItem('voe_private_key');
}
export async function decryptWithPrivateKey(
	encrypted: string,
	privateKey: string
): Promise<string> {
	const key = await crypto.subtle.importKey(
		'pkcs8',
		decode(privateKey),
		{ name: 'RSA-OAEP', hash: 'SHA-256' },
		false,
		['decrypt']
	);
	return new TextDecoder().decode(
		await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, key, decode(encrypted))
	);
}
