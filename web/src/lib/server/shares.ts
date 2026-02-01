import { randomUUID } from 'crypto';
import { eq, and, or, like, sql, isNull, gt } from 'drizzle-orm';
import { db } from './db';
import { folderShares, user } from './db/schema';
import type { InferSelectModel } from 'drizzle-orm';

export type FolderShare = InferSelectModel<typeof folderShares>;

export async function createShare(
	ownerId: string,
	sharedWithId: string,
	folderPath: string,
	permission: 'read' | 'readwrite',
	encryptedVaultPassword: string,
	expiresAt?: Date
): Promise<FolderShare> {
	const id = randomUUID();
	const now = new Date();

	await db.insert(folderShares).values({
		id,
		ownerId,
		sharedWithId,
		folderPath,
		permission,
		encryptedVaultPassword,
		createdAt: now,
		expiresAt
	});

	return {
		id,
		ownerId,
		sharedWithId,
		folderPath,
		permission,
		encryptedVaultPassword,
		createdAt: now,
		expiresAt: expiresAt ?? null
	};
}

export async function deleteShare(shareId: string, ownerId: string): Promise<boolean> {
	const result = await db
		.delete(folderShares)
		.where(and(eq(folderShares.id, shareId), eq(folderShares.ownerId, ownerId)))
		.returning();

	return result.length > 0;
}

export async function deleteShareByPath(
	ownerId: string,
	sharedWithId: string,
	folderPath: string
): Promise<boolean> {
	const result = await db
		.delete(folderShares)
		.where(
			and(
				eq(folderShares.ownerId, ownerId),
				eq(folderShares.sharedWithId, sharedWithId),
				eq(folderShares.folderPath, folderPath)
			)
		)
		.returning();

	return result.length > 0;
}

export async function getIncomingShares(userId: string): Promise<
	Array<FolderShare & { owner: { email: string; name: string } }>
> {
	const now = new Date();

	const shares = await db
		.select({
			share: folderShares,
			ownerEmail: user.email,
			ownerName: user.name
		})
		.from(folderShares)
		.innerJoin(user, eq(folderShares.ownerId, user.id))
		.where(
			and(
				eq(folderShares.sharedWithId, userId),
				or(
					isNull(folderShares.expiresAt),
					gt(folderShares.expiresAt, now)
				)
			)
		);

	return shares.map((s) => ({
		...s.share,
		owner: {
			email: s.ownerEmail,
			name: s.ownerName
		}
	}));
}

export async function getOutgoingShares(userId: string): Promise<
	Array<FolderShare & { sharedWith: { email: string; name: string } }>
> {
	const shares = await db
		.select({
			share: folderShares,
			sharedWithEmail: user.email,
			sharedWithName: user.name
		})
		.from(folderShares)
		.innerJoin(user, eq(folderShares.sharedWithId, user.id))
		.where(eq(folderShares.ownerId, userId));

	return shares.map((s) => ({
		...s.share,
		sharedWith: {
			email: s.sharedWithEmail,
			name: s.sharedWithName
		}
	}));
}

export async function getShareById(
	shareId: string,
	userId: string
): Promise<(FolderShare & { owner?: { email: string; name: string } }) | null> {
	const [share] = await db
		.select({
			share: folderShares,
			ownerEmail: user.email,
			ownerName: user.name
		})
		.from(folderShares)
		.leftJoin(user, eq(folderShares.ownerId, user.id))
		.where(
			and(
				eq(folderShares.id, shareId),
				or(eq(folderShares.ownerId, userId), eq(folderShares.sharedWithId, userId))
			)
		)
		.limit(1);

	if (!share) return null;

	return {
		...share.share,
		owner: share.ownerEmail
			? {
					email: share.ownerEmail,
					name: share.ownerName ?? share.ownerEmail
				}
			: undefined
	};
}

export async function hasShareAccess(
	userId: string,
	folderPath: string,
	requiredPermission?: 'read' | 'readwrite'
): Promise<{
	hasAccess: boolean;
	permission?: 'read' | 'readwrite';
	encryptedVaultPassword?: string;
}> {
	const now = new Date();

	// Check if user has access to this folder path
	// A share grants access to the shared folder and all its subfolders
	// So if share is for "org:product", user can access "org:product", "org:product:dev", etc.
	const [share] = await db
		.select({
			permission: folderShares.permission,
			encryptedVaultPassword: folderShares.encryptedVaultPassword
		})
		.from(folderShares)
		.where(
			and(
				eq(folderShares.sharedWithId, userId),
				or(
					// Exact match: share for this exact path
					eq(folderShares.folderPath, folderPath),
					// Share is a parent: share path is a prefix of the requested path
					// e.g., share is "org:product" and user requests "org:product:dev"
					sql`${folderPath} LIKE ${folderShares.folderPath} || ':%'`
				),
				or(
					isNull(folderShares.expiresAt),
					gt(folderShares.expiresAt, now)
				)
			)
		)
		.limit(1);

	if (!share) {
		return { hasAccess: false };
	}

	if (requiredPermission === 'readwrite' && share.permission === 'read') {
		return { hasAccess: false };
	}

	return {
		hasAccess: true,
		permission: share.permission,
		encryptedVaultPassword: share.encryptedVaultPassword
	};
}

export async function getUserByEmail(email: string): Promise<{ id: string; email: string; name: string; publicKey: string | null } | null> {
	const [userRecord] = await db
		.select({
			id: user.id,
			email: user.email,
			name: user.name,
			publicKey: user.publicKey
		})
		.from(user)
		.where(eq(user.email, email))
		.limit(1);

	return userRecord || null;
}

export async function getUserPublicKey(userId: string): Promise<string | null> {
	const [userRecord] = await db
		.select({
			publicKey: user.publicKey
		})
		.from(user)
		.where(eq(user.id, userId))
		.limit(1);

	return userRecord?.publicKey || null;
}

export async function setUserPublicKey(userId: string, publicKey: string): Promise<boolean> {
	const result = await db
		.update(user)
		.set({ publicKey })
		.where(eq(user.id, userId))
		.returning();

	return result.length > 0;
}

export async function updateSharePermission(
	shareId: string,
	ownerId: string,
	permission: 'read' | 'readwrite'
): Promise<boolean> {
	const result = await db
		.update(folderShares)
		.set({ permission })
		.where(and(eq(folderShares.id, shareId), eq(folderShares.ownerId, ownerId)))
		.returning();

	return result.length > 0;
}
