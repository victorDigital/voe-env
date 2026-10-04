import { describe, test, expect } from 'bun:test';
import {
	bytes,
	randomKey,
	seal,
	unseal,
	identityKeyPair,
	wrapTo,
	unwrapFrom,
	derivePrf
} from '../src/lib/vault-crypto';
import { context, secretContext, folderContext, orgContext } from '../src/lib/vault-format';
import { validateTree } from '../src/lib/server/vault-validation';
import { permits } from '../src/lib/permissions';
describe('versioned vault encryption', () => {
	test('authenticates organization, folder, secret name, ID and epoch', async () => {
		const key = randomKey();
		const ctx = secretContext('org', 'folder', 'id', 'NAME', 1);
		const sealed = await seal(key, bytes('private value'), ctx);
		expect(new TextDecoder().decode(await unseal(key, sealed, ctx))).toBe('private value');
		for (const changed of [
			secretContext('other', 'folder', 'id', 'NAME', 1),
			secretContext('org', 'other', 'id', 'NAME', 1),
			secretContext('org', 'folder', 'other', 'NAME', 1),
			secretContext('org', 'folder', 'id', 'OTHER', 1),
			secretContext('org', 'folder', 'id', 'NAME', 2)
		])
			await expect(unseal(key, sealed, changed)).rejects.toThrow();
		await expect(unseal(randomKey(), sealed, ctx)).rejects.toThrow();
		expect(await seal(key, bytes('private value'), ctx)).not.toBe(sealed);
	});
	test('rejects tampering and unknown formats', async () => {
		const key = randomKey();
		const sealed = await seal(key, bytes('hello'), 'ctx');
		const tampered = sealed.slice(0, -5) + 'AAAAA';
		await expect(unseal(key, tampered, 'ctx')).rejects.toThrow();
		await expect(unseal(key, 'v2.abc', 'ctx')).rejects.toThrow();
	});
	test('organization envelopes are bound to recipient and epoch', async () => {
		const pair = await identityKeyPair();
		const key = randomKey();
		const aad = orgContext('org', 'user:a', 1);
		const wrapped = await wrapTo(pair.publicKey, key, aad);
		expect(await unwrapFrom(pair.privateKey, wrapped, aad)).toEqual(key);
		await expect(
			unwrapFrom(pair.privateKey, wrapped, orgContext('org', 'user:b', 1))
		).rejects.toThrow();
		await expect(
			unwrapFrom(pair.privateKey, wrapped, orgContext('org', 'user:a', 2))
		).rejects.toThrow();
	});
	test('backup passkeys and recovery unlock the same account with independent envelopes', async () => {
		const account = randomKey();
		const recovery = randomKey();
		const first = await derivePrf(randomKey(), 'a');
		const second = await derivePrf(randomKey(), 'a');
		for (const [name, key] of [
			['passkey1', first],
			['passkey2', second],
			['recovery', recovery]
		] as const) {
			const envelope = await seal(key, account, context(name, 'a'));
			expect(await unseal(key, envelope, context(name, 'a'))).toEqual(account);
			await expect(unseal(randomKey(), envelope, context(name, 'a'))).rejects.toThrow();
		}
	});
	test('fresh folder keys prevent old-key reads after rotation', async () => {
		const old = randomKey(),
			fresh = randomKey();
		const value = await seal(fresh, bytes('new value'), folderContext('org', 'f', 2));
		await expect(unseal(old, value, folderContext('org', 'f', 2))).rejects.toThrow();
	});
});
describe('workspace invariants', () => {
	const root = { id: 'root', name: '', parentId: null, wrappedKey: 'x' };
	test('rejects missing roots, duplicate siblings, cycles, and foreign folders', () => {
		expect(() => validateTree([], [])).toThrow();
		expect(() => validateTree([root, { ...root }], [])).toThrow();
		expect(() =>
			validateTree([root, { id: 'x', name: 'x', parentId: 'x', wrappedKey: 'x' }], [])
		).toThrow();
		expect(() =>
			validateTree([root], [{ id: 's', folderId: 'foreign', name: 'KEY', encryptedValue: 'x' }])
		).toThrow();
		expect(() =>
			validateTree(
				[
					root,
					{ id: 'a', name: 'same', parentId: 'root', wrappedKey: 'x' },
					{ id: 'b', name: 'same', parentId: 'root', wrappedKey: 'x' }
				],
				[]
			)
		).toThrow();
	});
	test('accepts empty folders and duplicate names in different parents', () => {
		expect(() =>
			validateTree(
				[
					root,
					{ id: 'a', name: 'a', parentId: 'root', wrappedKey: 'x' },
					{ id: 'b', name: 'a', parentId: 'a', wrappedKey: 'x' }
				],
				[]
			)
		).not.toThrow();
	});
	test.each(['owner', 'admin', 'member', 'viewer'])('enforces %s role', (role) => {
		expect(permits(role, 'read')).toBe(true);
		expect(permits(role, 'write')).toBe(role !== 'viewer');
		expect(permits(role, 'provision')).toBe(role === 'owner' || role === 'admin');
	});
	test('unknown roles have no permissions', () => {
		expect(permits('owner,member', 'write')).toBe(false);
		expect(permits('unknown', 'read')).toBe(false);
	});
});

test('shared browser/Rust fixtures retain exact UTF-8 values', async () => {
	const fixture = await Bun.file(new URL('./fixtures/vault-v1.json', import.meta.url)).json();
	const { decode } = await import('../src/lib/vault-crypto');
	expect(
		new TextDecoder().decode(await unseal(decode(fixture.key), fixture.ciphertext, fixture.aad))
	).toBe(fixture.plaintext);
	expect(await unwrapFrom(decode(fixture.privateKey), fixture.wrappedKey, fixture.rsaAad)).toEqual(
		decode(fixture.key)
	);
});
