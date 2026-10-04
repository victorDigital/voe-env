import { writable } from 'svelte/store';
import { authClient } from './auth-client';
import {
	bytes,
	decode,
	encode,
	randomKey,
	seal,
	unseal,
	derivePrf,
	identityKeyPair,
	wrapTo,
	unwrapFrom
} from './vault-crypto';
import {
	context,
	folderContext,
	orgContext,
	secretContext,
	type WorkspaceSnapshot
} from './vault-format';
export async function api<T>(path: string, body?: unknown): Promise<T> {
	const response = await fetch(path, {
		method: body ? 'POST' : 'GET',
		headers: body ? { 'Content-Type': 'application/json' } : {},
		body: body ? JSON.stringify(body) : undefined
	});
	const result = await response.json();
	if (response.status === 401) lock();
	if (!response.ok) throw new Error(result.message || result.error || 'Request failed');
	return result as T;
}
type Identity = {
	userId: string;
	publicKey: string;
	encryptedPrivateKey: string;
	recoveryEnvelope: string;
};
type IdentityResponse = {
	identity: Identity | null;
	envelopes: { credentialId: string; wrappedKey: string }[];
};
type Unlocked = {
	userId: string;
	accountKey: Uint8Array<ArrayBuffer>;
	privateKey: Uint8Array<ArrayBuffer>;
	publicKey: string;
};
let unlocked: Unlocked | null = null;
let lockTimer: ReturnType<typeof setTimeout> | undefined;
export const isUnlocked = writable(false);
export function lock() {
	unlocked?.accountKey.fill(0);
	unlocked?.privateKey.fill(0);
	unlocked = null;
	clearTimeout(lockTimer);
	isUnlocked.set(false);
}
function remember(value: Unlocked) {
	lock();
	unlocked = value;
	isUnlocked.set(true);
	lockTimer = setTimeout(lock, 15 * 60 * 1000);
}
export function identity() {
	if (!unlocked) throw new Error('Unlock your vault first');
	return unlocked;
}
const prfInput = bytes('voe.account-unlock.prf.v1');
const extensions: NonNullable<Parameters<typeof authClient.signIn.passkey>[0]>['extensions'] & {
	prf: { eval: { first: Uint8Array<ArrayBuffer> } };
} = { prf: { eval: { first: prfInput } } };
function prfResult(result: unknown) {
	const value = (
		result as {
			webauthn?: {
				response: { id: string };
				clientExtensionResults: { prf?: { results?: { first: ArrayBuffer } } };
			};
		}
	).webauthn;
	if (!value?.clientExtensionResults.prf?.results?.first)
		throw new Error(
			'This passkey does not support encrypted vault unlock. Use a PRF-capable passkey or your recovery key.'
		);
	return {
		credentialId: value.response.id,
		output: new Uint8Array(value.clientExtensionResults.prf.results.first)
	};
}
export async function signInAndUnlock() {
	lock();
	const result = await authClient.signIn.passkey({ extensions, returnWebAuthnResponse: true });
	if (result.error) throw new Error(result.error.message || 'Passkey sign-in failed');
	const data = await api<IdentityResponse>('/api/identity');
	if (!data.identity) return;
	const prf = prfResult(result);
	const envelope = data.envelopes.find((e) => e.credentialId === prf.credentialId);
	if (!envelope)
		throw new Error(
			'This passkey has no encryption access. Use an enrolled passkey or recover your vault.'
		);
	const key = await derivePrf(prf.output, data.identity.userId);
	prf.output.fill(0);
	const accountKey = await unseal(
		key,
		envelope.wrappedKey,
		context('account', data.identity.userId, prf.credentialId)
	);
	key.fill(0);
	const privateKey = await unseal(
		accountKey,
		data.identity.encryptedPrivateKey,
		context('identity', data.identity.userId)
	);
	remember({
		userId: data.identity.userId,
		accountKey,
		privateKey,
		publicKey: data.identity.publicKey
	});
}
async function register() {
	const result = await authClient.passkey.addPasskey({
		name: 'VOE vault',
		extensions,
		returnWebAuthnResponse: true
	});
	if (result.error) throw new Error(result.error.message || 'Passkey registration failed');
	try {
		return prfResult(result);
	} catch {
		const signin = await authClient.signIn.passkey({ extensions, returnWebAuthnResponse: true });
		if (signin.error) throw new Error(signin.error.message || 'Verify your new passkey');
		const prf = prfResult(signin);
		if (prf.credentialId !== result.data?.credentialID)
			throw new Error('Choose the passkey you just created');
		return prf;
	}
}
const hash = async (value: Uint8Array<ArrayBuffer>) =>
	Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', value)), (b) =>
		b.toString(16).padStart(2, '0')
	).join('');
export async function recoveryProof(key: Uint8Array<ArrayBuffer>) {
	return hash(new Uint8Array([...bytes('voe.recovery.authentication.v1'), ...key]));
}
export type PendingSetup = {
	recoveryKey: string;
	commit: () => Promise<void>;
	discard: () => void;
};
export async function beginSetup(userId: string): Promise<PendingSetup> {
	const existing = await api<IdentityResponse>('/api/identity');
	if (existing.identity)
		throw new Error('An encryption identity already exists. Unlock or recover it.');
	const prf = await register();
	const wrappingKey = await derivePrf(prf.output, userId);
	prf.output.fill(0);
	const accountKey = randomKey();
	const recovery = randomKey();
	const pair = await identityKeyPair();
	const wrappedKey = await seal(
		wrappingKey,
		accountKey,
		context('account', userId, prf.credentialId)
	);
	wrappingKey.fill(0);
	const encryptedPrivateKey = await seal(accountKey, pair.privateKey, context('identity', userId));
	const recoveryEnvelope = await seal(recovery, accountKey, context('recovery', userId));
	const recoveryAuthHash = await hash(bytes(await recoveryProof(recovery)));
	const recoveryKey = encode(recovery);
	recovery.fill(0);
	return {
		recoveryKey,
		discard: () => {
			accountKey.fill(0);
			pair.privateKey.fill(0);
		},
		commit: async () => {
			await api('/api/identity', {
				credentialId: prf.credentialId,
				wrappedKey,
				publicKey: pair.publicKey,
				encryptedPrivateKey,
				recoveryEnvelope,
				recoveryAuthHash
			});
			remember({ userId, accountKey, privateKey: pair.privateKey, publicKey: pair.publicKey });
		}
	};
}
export async function recover(recoveryKey: string) {
	const data = await api<IdentityResponse>('/api/identity');
	if (!data.identity) throw new Error('No encrypted account exists');
	const key = decode(recoveryKey.trim());
	if (key.length !== 32) throw new Error('Invalid recovery key');
	const accountKey = await unseal(
		key,
		data.identity.recoveryEnvelope,
		context('recovery', data.identity.userId)
	);
	const privateKey = await unseal(
		accountKey,
		data.identity.encryptedPrivateKey,
		context('identity', data.identity.userId)
	);
	const proof = await recoveryProof(key);
	key.fill(0);
	await api('/api/identity', { action: 'recover', proof });
	remember({
		userId: data.identity.userId,
		accountKey,
		privateKey,
		publicKey: data.identity.publicKey
	});
}
export async function addBackupPasskey() {
	const current = identity();
	const prf = await register();
	const key = await derivePrf(prf.output, current.userId);
	prf.output.fill(0);
	const wrappedKey = await seal(
		key,
		current.accountKey,
		context('account', current.userId, prf.credentialId)
	);
	key.fill(0);
	await api('/api/identity', { credentialId: prf.credentialId, wrappedKey });
}
export type Directory = {
	members: {
		userId: string;
		name: string;
		email: string;
		role: string;
		publicKey: string | null;
	}[];
	devices: { id: string; userId: string | null; publicKey: string }[];
	recipients: string[];
	bindings: { recipient: string; identityBinding: string }[];
};
export type Snapshot = WorkspaceSnapshot & Directory;
export async function organizationKey(snapshot: WorkspaceSnapshot) {
	const current = identity();
	const recipient = `user:${current.userId}`;
	const envelope = snapshot.envelopes.find((e) => e.recipient === recipient);
	if (!envelope)
		throw new Error('Awaiting key approval. Ask a workspace admin to grant encryption access.');
	return unwrapFrom(
		current.privateKey,
		envelope.wrappedKey,
		orgContext(snapshot.organizationId, recipient, snapshot.epoch)
	);
}
export async function initializeWorkspace(organizationId: string) {
	const current = identity();
	const key = randomKey();
	const folderKey = randomKey();
	const id = crypto.randomUUID();
	const recipient = `user:${current.userId}`;
	await api(`/api/workspaces/${organizationId}`, {
		action: 'initialize',
		revision: 0,
		epoch: 1,
		folders: [
			{
				id,
				name: '',
				parentId: null,
				wrappedKey: await seal(key, folderKey, folderContext(organizationId, id, 1))
			}
		],
		secrets: [],
		envelopes: [
			{
				recipient,
				wrappedKey: await wrapTo(current.publicKey, key, orgContext(organizationId, recipient, 1)),
				identityBinding: await seal(
					key,
					bytes(current.publicKey),
					context('recipient', organizationId, recipient, 1)
				)
			}
		]
	});
	key.fill(0);
	folderKey.fill(0);
}
export async function decryptWorkspace(snapshot: WorkspaceSnapshot) {
	const current = identity();
	const orgKey = await organizationKey(snapshot);
	const values: Record<string, string> = {};
	try {
		for (const folder of snapshot.folders) {
			const key = await unseal(
				orgKey,
				folder.wrappedKey,
				folderContext(snapshot.organizationId, folder.id, snapshot.epoch)
			);
			try {
				for (const secret of snapshot.secrets.filter((s) => s.folderId === folder.id))
					values[secret.id] = new TextDecoder('utf-8', { fatal: true }).decode(
						await unseal(
							key,
							secret.encryptedValue,
							secretContext(
								snapshot.organizationId,
								folder.id,
								secret.id,
								secret.name,
								snapshot.epoch
							)
						)
					);
			} finally {
				key.fill(0);
			}
		}
		if (unlocked !== current) throw new Error('Vault was locked during decryption');
		return values;
	} finally {
		orgKey.fill(0);
	}
}
export async function rotateWorkspace(snapshot: Snapshot) {
	const values = await decryptWorkspace(snapshot);
	const oldKey = await organizationKey(snapshot);
	const key = randomKey();
	const epoch = snapshot.epoch + 1;
	const folders = [];
	const secrets = [];
	const envelopes = [];
	for (const folder of snapshot.folders) {
		const folderKey = randomKey();
		folders.push({
			...folder,
			wrappedKey: await seal(
				key,
				folderKey,
				folderContext(snapshot.organizationId, folder.id, epoch)
			)
		});
		for (const secret of snapshot.secrets.filter((s) => s.folderId === folder.id))
			secrets.push({
				...secret,
				encryptedValue: await seal(
					folderKey,
					bytes(values[secret.id]),
					secretContext(snapshot.organizationId, folder.id, secret.id, secret.name, epoch)
				)
			});
		folderKey.fill(0);
	}
	for (const recipient of snapshot.recipients) {
		const binding = snapshot.bindings.find((b) => b.recipient === recipient);
		if (!binding) throw new Error('A recipient has no verified key binding');
		const publicKey = new TextDecoder().decode(
			await unseal(
				oldKey,
				binding.identityBinding,
				context('recipient', snapshot.organizationId, recipient, snapshot.epoch)
			)
		);
		envelopes.push({
			recipient,
			wrappedKey: await wrapTo(
				publicKey,
				key,
				orgContext(snapshot.organizationId, recipient, epoch)
			),
			identityBinding: await seal(
				key,
				bytes(publicKey),
				context('recipient', snapshot.organizationId, recipient, epoch)
			)
		});
	}
	key.fill(0);
	oldKey.fill(0);
	await api(`/api/workspaces/${snapshot.organizationId}`, {
		action: 'rotate',
		revision: snapshot.revision,
		epoch,
		folders,
		secrets,
		envelopes
	});
}
