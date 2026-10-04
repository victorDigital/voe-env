import { z } from 'zod';
import type { Folder, Secret } from '../vault-format';
export const id = z
	.string()
	.min(1)
	.max(128)
	.regex(/^[a-zA-Z0-9_-]+$/);
export const aesEnvelope = z
	.string()
	.max(1_400_000)
	.regex(/^v1\.[A-Za-z0-9+/]+={0,2}$/)
	.refine((v) => Buffer.from(v.slice(3), 'base64').length >= 28);
export const rsaEnvelope = z
	.string()
	.regex(/^rsa1\.[A-Za-z0-9+/]+={0,2}$/)
	.refine((v) => Buffer.from(v.slice(5), 'base64').length === 384);
export const publicKey = z
	.string()
	.min(500)
	.max(1000)
	.regex(/^[A-Za-z0-9+/]+={0,2}$/);
export const folderSchema = z.object({
	id,
	parentId: id.nullable(),
	name: z
		.string()
		.max(128)
		.refine((v) => !v.includes(':') && !/[\x00-\x1f]/.test(v)),
	wrappedKey: aesEnvelope
});
export const secretSchema = z.object({
	id,
	folderId: id,
	name: z
		.string()
		.regex(/^[A-Za-z_][A-Za-z0-9_]*$/)
		.max(256),
	encryptedValue: aesEnvelope
});
export const envelopeSchema = z.object({
	recipient: z.string().regex(/^(user|device):[a-zA-Z0-9_-]+$/),
	wrappedKey: rsaEnvelope,
	identityBinding: aesEnvelope
});
export const snapshotSchema = z.object({
	revision: z.number().int().nonnegative(),
	epoch: z.number().int().positive(),
	folders: z.array(folderSchema).min(1).max(2000),
	secrets: z.array(secretSchema).max(10000),
	envelopes: z.array(envelopeSchema).max(1000).optional()
});
export function validateTree(folders: Folder[], secrets: Secret[]) {
	const byId = new Map(folders.map((f) => [f.id, f]));
	if (byId.size !== folders.length || folders.filter((f) => f.parentId === null).length !== 1)
		throw new Error('Exactly one root folder and unique IDs are required');
	const siblings = new Set<string>();
	for (const folder of folders) {
		if (folder.parentId === null ? folder.name !== '' : !folder.name.trim())
			throw new Error('Invalid folder name');
		const sibling = JSON.stringify([folder.parentId, folder.name]);
		if (siblings.has(sibling)) throw new Error('Duplicate folder name');
		siblings.add(sibling);
		const visited = new Set([folder.id]);
		let parent = folder.parentId;
		while (parent !== null) {
			if (visited.has(parent) || !byId.has(parent)) throw new Error('Invalid folder ancestry');
			visited.add(parent);
			parent = byId.get(parent)!.parentId;
			if (visited.size > 64) throw new Error('Folder nesting is too deep');
		}
	}
	const names = new Set<string>();
	const ids = new Set<string>();
	for (const secret of secrets) {
		const name = JSON.stringify([secret.folderId, secret.name]);
		if (!byId.has(secret.folderId) || names.has(name) || ids.has(secret.id))
			throw new Error('Invalid or duplicate secret');
		names.add(name);
		ids.add(secret.id);
	}
}
