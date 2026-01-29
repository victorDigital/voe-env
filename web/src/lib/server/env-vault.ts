import { randomUUID } from 'crypto';
import { eq, like, and } from 'drizzle-orm';
import { db } from './db';
import { envVault } from './db/schema';

export async function setEnv(
	userId: string,
	fullKey: string,
	encryptedValue: string
): Promise<void> {
	const now = new Date().toISOString();

	await db
		.insert(envVault)
		.values({
			id: randomUUID(),
			userId,
			fullKey,
			encryptedValue,
			createdAt: now,
			updatedAt: now
		})
		.onConflictDoUpdate({
			target: envVault.userKeyUnique,
			set: { encryptedValue, updatedAt: now }
		});
}

export async function getEnv(userId: string, fullKey: string): Promise<string | null> {
	const result = await db
		.select()
		.from(envVault)
		.where(and(eq(envVault.userId, userId), eq(envVault.fullKey, fullKey)))
		.limit(1);
	if (result.length === 0) return null;
	return result[0].encryptedValue;
}

export async function listEnv(
	userId: string,
	prefix: string
): Promise<{ type: 'folder' | 'key'; name: string }[]> {
	const searchPrefix = prefix ? `${prefix}:` : '';
	const results = await db
		.select({ fullKey: envVault.fullKey })
		.from(envVault)
		.where(and(eq(envVault.userId, userId), like(envVault.fullKey, `${searchPrefix}%`)));
	const items = new Map<string, 'folder' | 'key'>();
	for (const { fullKey } of results) {
		const remaining = fullKey.slice(searchPrefix.length);
		const parts = remaining.split(':');
		const name = parts[0];
		const type = parts.length > 1 ? 'folder' : 'key';
		if (!items.has(name) || type === 'folder') {
			// Prefer folder if conflict, but shouldn't happen
			items.set(name, type);
		}
	}
	return Array.from(items.entries()).map(([name, type]) => ({ name, type }));
}

export async function getAllEnv(userId: string): Promise<Record<string, string>> {
	const results = await db
		.select({ fullKey: envVault.fullKey, encryptedValue: envVault.encryptedValue })
		.from(envVault)
		.where(eq(envVault.userId, userId));

	const envs: Record<string, string> = {};
	for (const { fullKey, encryptedValue } of results) {
		envs[fullKey] = encryptedValue;
	}
	return envs;
}

export async function getVaultEnv(
	userId: string,
	vaultPath: string
): Promise<Record<string, string>> {
	const searchPrefix = vaultPath ? `${vaultPath}:` : '';
	const results = await db
		.select({ fullKey: envVault.fullKey, encryptedValue: envVault.encryptedValue })
		.from(envVault)
		.where(and(eq(envVault.userId, userId), like(envVault.fullKey, `${searchPrefix}%`)));

	const envs: Record<string, string> = {};
	for (const { fullKey, encryptedValue } of results) {
		// Extract the key part after the vault path prefix
		const key = vaultPath ? fullKey.slice(searchPrefix.length) : fullKey;
		// Only include direct children (no nested paths)
		if (!key.includes(':')) {
			envs[key] = encryptedValue;
		}
	}
	return envs;
}

export async function deleteEnv(userId: string, fullKey: string): Promise<void> {
	await db.delete(envVault).where(and(eq(envVault.userId, userId), eq(envVault.fullKey, fullKey)));
}
