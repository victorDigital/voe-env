import { and, eq, gt, isNull, or } from 'drizzle-orm';
import { db } from './db';
import { folderShares, user } from './db/schema';
export async function getIncomingShares(userId: string) {
	const rows = await db
		.select({ share: folderShares, ownerEmail: user.email, ownerName: user.name })
		.from(folderShares)
		.innerJoin(user, eq(folderShares.ownerId, user.id))
		.where(
			and(
				eq(folderShares.sharedWithId, userId),
				or(isNull(folderShares.expiresAt), gt(folderShares.expiresAt, new Date()))
			)
		);
	return rows.map((row) => ({
		...row.share,
		owner: { email: row.ownerEmail, name: row.ownerName }
	}));
}
