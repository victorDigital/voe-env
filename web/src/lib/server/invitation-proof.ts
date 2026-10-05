import { createHash, randomBytes } from 'node:crypto';
import { and, eq, gt } from 'drizzle-orm';
import { db } from './db';
import { invitation, organization, verification } from './db/schema';
import type { Transaction } from './vault-access';

const identifier = (id: string) => `invitation-auth:${id}`;
const digest = (token: string) => createHash('sha256').update(token).digest('hex');

export async function issueInvitationProof(id: string) {
	return db.transaction(async (tx) => {
		const [invite] = await tx.select().from(invitation).where(eq(invitation.id, id)).for('update');
		if (!invite || invite.status !== 'pending' || invite.expiresAt <= new Date())
			throw new Error('Invitation is no longer available.');
		const token = randomBytes(32).toString('base64url');
		await tx.delete(verification).where(eq(verification.identifier, identifier(id)));
		await tx.insert(verification).values({
			id: crypto.randomUUID(),
			identifier: identifier(id),
			value: digest(token),
			expiresAt: invite.expiresAt
		});
		return token;
	});
}

export async function readInvitationProof(
	id: string,
	token: string,
	tx: typeof db | Transaction = db
) {
	if (!/^[A-Za-z0-9_-]{43}$/.test(token)) return null;
	const [invite] = await tx
		.select({
			id: invitation.id,
			email: invitation.email,
			role: invitation.role,
			organizationId: invitation.organizationId,
			organizationName: organization.name
		})
		.from(invitation)
		.innerJoin(organization, eq(organization.id, invitation.organizationId))
		.innerJoin(verification, eq(verification.identifier, identifier(id)))
		.where(
			and(
				eq(invitation.id, id),
				eq(invitation.status, 'pending'),
				gt(invitation.expiresAt, new Date()),
				gt(verification.expiresAt, new Date()),
				eq(verification.value, digest(token))
			)
		);
	return invite || null;
}

export async function consumeInvitationProof(id: string, token: string) {
	return db.transaction(async (tx) => {
		await tx
			.select({ id: invitation.id })
			.from(invitation)
			.where(eq(invitation.id, id))
			.for('update');
		const invite = await readInvitationProof(id, token, tx);
		if (!invite) return null;
		await tx.delete(verification).where(eq(verification.identifier, identifier(id)));
		return invite;
	});
}
