import { and, eq } from 'drizzle-orm';
import { db } from './db';
import { accountEnvelope, encryptionIdentity, passkeyVerification } from './db/schema';
export async function recentlyVerified(
	sessionId: string,
	userId: string,
	initial = false,
	maxAge = 5 * 60 * 1000
) {
	const [proof] = await db
		.select()
		.from(passkeyVerification)
		.where(eq(passkeyVerification.sessionId, sessionId));
	if (!proof || Date.now() - proof.verifiedAt.getTime() > maxAge) return false;
	if (proof.recovery) return true;
	if (!proof.credentialId) return false;
	const [envelope] = await db
		.select()
		.from(accountEnvelope)
		.where(
			and(eq(accountEnvelope.userId, userId), eq(accountEnvelope.credentialId, proof.credentialId))
		);
	if (envelope) return true;
	const [identity] = await db
		.select()
		.from(encryptionIdentity)
		.where(eq(encryptionIdentity.userId, userId));
	return initial && !identity;
}
