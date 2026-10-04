import { eq } from 'drizzle-orm';
import { db } from './db';
import { envVault } from './db/schema';
export async function getAllEnv(userId: string): Promise<Record<string, string>> {
	const rows = await db
		.select({ fullKey: envVault.fullKey, encryptedValue: envVault.encryptedValue })
		.from(envVault)
		.where(eq(envVault.userId, userId));
	return Object.fromEntries(rows.map((row) => [row.fullKey, row.encryptedValue]));
}
