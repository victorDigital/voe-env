// Client-side cryptography utilities for E2E encryption
// Uses RSA-OAEP for asymmetric encryption (sharing) and AES-GCM for symmetric encryption (vault data)

const STORAGE_KEY_PRIVATE = 'voe_private_key';
const STORAGE_KEY_PUBLIC = 'voe_public_key';

// Generate RSA key pair for sharing
export async function generateKeyPair(): Promise<{ publicKey: string; privateKey: string }> {
	const keyPair = await crypto.subtle.generateKey(
		{
			name: 'RSA-OAEP',
			modulusLength: 2048,
			publicExponent: new Uint8Array([1, 0, 1]),
			hash: 'SHA-256'
		},
		true, // extractable
		['encrypt', 'decrypt']
	);

	const publicKeyBuffer = await crypto.subtle.exportKey('spki', keyPair.publicKey);
	const privateKeyBuffer = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);

	const publicKey = btoa(String.fromCharCode(...new Uint8Array(publicKeyBuffer)));
	const privateKey = btoa(String.fromCharCode(...new Uint8Array(privateKeyBuffer)));

	return { publicKey, privateKey };
}

// Import public key from base64 string
export async function importPublicKey(publicKeyBase64: string): Promise<CryptoKey> {
	const keyData = Uint8Array.from(atob(publicKeyBase64), (c) => c.charCodeAt(0));
	return crypto.subtle.importKey(
		'spki',
		keyData,
		{ name: 'RSA-OAEP', hash: 'SHA-256' },
		false,
		['encrypt']
	);
}

// Import private key from base64 string
export async function importPrivateKey(privateKeyBase64: string): Promise<CryptoKey> {
	const keyData = Uint8Array.from(atob(privateKeyBase64), (c) => c.charCodeAt(0));
	return crypto.subtle.importKey(
		'pkcs8',
		keyData,
		{ name: 'RSA-OAEP', hash: 'SHA-256' },
		false,
		['decrypt']
	);
}

// Encrypt data with recipient's public key (for sharing vault password)
export async function encryptWithPublicKey(data: string, publicKeyBase64: string): Promise<string> {
	const publicKey = await importPublicKey(publicKeyBase64);
	const encrypted = await crypto.subtle.encrypt(
		{ name: 'RSA-OAEP' },
		publicKey,
		new TextEncoder().encode(data)
	);
	return btoa(String.fromCharCode(...new Uint8Array(encrypted)));
}

// Decrypt data with own private key (for receiving shared vault password)
export async function decryptWithPrivateKey(encryptedBase64: string, privateKeyBase64: string): Promise<string> {
	const privateKey = await importPrivateKey(privateKeyBase64);
	const encryptedData = Uint8Array.from(atob(encryptedBase64), (c) => c.charCodeAt(0));
	const decrypted = await crypto.subtle.decrypt(
		{ name: 'RSA-OAEP' },
		privateKey,
		encryptedData
	);
	return new TextDecoder().decode(decrypted);
}

// Store keys in localStorage
export function storePrivateKey(privateKey: string): void {
	localStorage.setItem(STORAGE_KEY_PRIVATE, privateKey);
}

export function storePublicKey(publicKey: string): void {
	localStorage.setItem(STORAGE_KEY_PUBLIC, publicKey);
}

export function getStoredPrivateKey(): string | null {
	return localStorage.getItem(STORAGE_KEY_PRIVATE);
}

export function getStoredPublicKey(): string | null {
	return localStorage.getItem(STORAGE_KEY_PUBLIC);
}

export function hasStoredKeys(): boolean {
	return !!(getStoredPrivateKey() && getStoredPublicKey());
}

export function clearStoredKeys(): void {
	localStorage.removeItem(STORAGE_KEY_PRIVATE);
	localStorage.removeItem(STORAGE_KEY_PUBLIC);
}

// Initialize keys: check if we have local keys, if not generate new ones
// Returns the public key to be sent to the server
export async function initializeKeys(): Promise<{ publicKey: string; isNew: boolean }> {
	const storedPublic = getStoredPublicKey();
	const storedPrivate = getStoredPrivateKey();

	if (storedPublic && storedPrivate) {
		// Verify the keys are valid by trying to import them
		try {
			await importPrivateKey(storedPrivate);
			await importPublicKey(storedPublic);
			return { publicKey: storedPublic, isNew: false };
		} catch {
			// Keys are invalid, regenerate
			console.warn('Stored keys invalid, regenerating...');
		}
	}

	// Generate new key pair
	const { publicKey, privateKey } = await generateKeyPair();
	storePrivateKey(privateKey);
	storePublicKey(publicKey);
	return { publicKey, isNew: true };
}
