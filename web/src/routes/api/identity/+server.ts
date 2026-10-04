import { revokeDevices } from '#lib/server/device-revocation.ts';
import { jsonEndpoint, readJson } from '#lib/server/json-endpoint.ts';
import { error, json } from '@sveltejs/kit';
import { and, eq, ne, inArray, sql } from 'drizzle-orm';
import { z } from 'zod';
import { createHash, timingSafeEqual } from 'node:crypto';
import { db } from '#lib/server/db/index.ts';
import {
	accountEnvelope,
	encryptionIdentity,
	passkey,
	passkeyVerification,
	session,
	encryptionDevice,
	organizationEnvelope,
	workspace,
	member,
	user as userTable,
	auditEvent
} from '#lib/server/db/schema.ts';
import { authenticated } from '#lib/server/vault-access.ts';
import { recentlyVerified } from '#lib/server/recent-verification.ts';
import { aesEnvelope, publicKey } from '#lib/server/vault-validation.ts';
import type { RequestHandler } from './$types';
export const GET: RequestHandler = async (event) => {
	const { user } = authenticated(event);
	const [identity] = await db
		.select({
			userId: encryptionIdentity.userId,
			publicKey: encryptionIdentity.publicKey,
			encryptedPrivateKey: encryptionIdentity.encryptedPrivateKey,
			recoveryEnvelope: encryptionIdentity.recoveryEnvelope
		})
		.from(encryptionIdentity)
		.where(eq(encryptionIdentity.userId, user.id));
	const envelopes = await db
		.select()
		.from(accountEnvelope)
		.where(eq(accountEnvelope.userId, user.id));
	return json(
		{ identity: identity || null, envelopes },
		{ headers: { 'Cache-Control': 'no-store' } }
	);
};
const enrollment = z.object({ credentialId: z.string().min(1).max(1024), wrappedKey: aesEnvelope });
const setup = enrollment.extend({
	publicKey,
	encryptedPrivateKey: aesEnvelope,
	recoveryEnvelope: aesEnvelope,
	recoveryAuthHash: z.string().regex(/^[a-f0-9]{64}$/)
});
const post: RequestHandler = async (event) => {
	const { user, session: current } = authenticated(event);
	if (!user.emailVerified) error(403, 'Verify your email first');
	const body = await readJson(event.request);
	if (body.action === 'reset') {
		if (body.confirm !== 'RESET' || Date.now() - new Date(current.createdAt).getTime() > 300_000)
			error(403, 'Sign in again using an email link, then confirm RESET');
		await db.transaction(async (tx) => {
			await tx.select().from(userTable).where(eq(userTable.id, user.id)).for('update');
			const memberships = await tx.select().from(member).where(eq(member.userId, user.id));
			for (const membership of memberships.sort((a, b) =>
				a.organizationId.localeCompare(b.organizationId)
			)) {
				await tx
					.select()
					.from(workspace)
					.where(eq(workspace.organizationId, membership.organizationId))
					.for('update');
				const [state] = await tx
					.select()
					.from(workspace)
					.where(eq(workspace.organizationId, membership.organizationId));
				if (!state) continue;
				const managers = await tx
					.select()
					.from(member)
					.where(
						and(
							eq(member.organizationId, membership.organizationId),
							ne(member.userId, user.id),
							inArray(member.role, ['owner', 'admin'])
						)
					);
				const available = managers.length
					? await tx
							.select()
							.from(organizationEnvelope)
							.where(
								and(
									eq(organizationEnvelope.organizationId, membership.organizationId),
									eq(organizationEnvelope.epoch, state.epoch),
									inArray(
										organizationEnvelope.recipient,
										managers.map((m) => `user:${m.userId}`)
									)
								)
							)
					: [];
				if (!available.length)
					error(
						409,
						'Every workspace needs another provisioned owner or admin before you can reset your identity. Use your recovery key for a personal workspace.'
					);
				await tx
					.delete(organizationEnvelope)
					.where(
						and(
							eq(organizationEnvelope.organizationId, membership.organizationId),
							eq(organizationEnvelope.recipient, `user:${user.id}`)
						)
					);
				await tx
					.update(workspace)
					.set({ rotationRequired: true, revision: sql`${workspace.revision}+1` })
					.where(eq(workspace.organizationId, membership.organizationId));
			}
			const devices = await tx
				.select()
				.from(encryptionDevice)
				.where(eq(encryptionDevice.userId, user.id));
			await revokeDevices(tx, devices);
			await tx.delete(encryptionIdentity).where(eq(encryptionIdentity.userId, user.id));
			await tx.delete(passkey).where(eq(passkey.userId, user.id));
			await tx.delete(session).where(and(eq(session.userId, user.id), ne(session.id, current.id)));
			await tx.delete(passkeyVerification).where(eq(passkeyVerification.sessionId, current.id));
			await tx
				.insert(auditEvent)
				.values({ id: crypto.randomUUID(), actorId: user.id, action: 'reset-encryption-identity' });
		});
		return json({ success: true });
	}
	if (body.action === 'recover') {
		const proof = z
			.string()
			.regex(/^[a-f0-9]{64}$/)
			.parse(body.proof);
		const [identity] = await db
			.select()
			.from(encryptionIdentity)
			.where(eq(encryptionIdentity.userId, user.id));
		const hash = createHash('sha256').update(proof).digest();
		if (!identity || !timingSafeEqual(hash, Buffer.from(identity.recoveryAuthHash, 'hex')))
			error(403, 'Recovery key is incorrect');
		await db.transaction(async (tx) => {
			const devices = await tx
				.select()
				.from(encryptionDevice)
				.where(eq(encryptionDevice.userId, user.id));
			await revokeDevices(tx, devices);
			await tx.delete(session).where(and(eq(session.userId, user.id), ne(session.id, current.id)));
			await tx
				.insert(passkeyVerification)
				.values({ sessionId: current.id, recovery: true })
				.onConflictDoUpdate({
					target: passkeyVerification.sessionId,
					set: { recovery: true, verifiedAt: new Date() }
				});
		});
		return json({ success: true });
	}
	if (!(await recentlyVerified(current.id, user.id, true)))
		error(403, 'Verify with your enrolled passkey first');
	const data = enrollment.parse(body);
	const [credential] = await db
		.select()
		.from(passkey)
		.where(and(eq(passkey.userId, user.id), eq(passkey.credentialID, data.credentialId)));
	if (!credential) error(400, 'Passkey does not belong to this account');
	await db.transaction(async (tx) => {
		const [identity] = await tx
			.select()
			.from(encryptionIdentity)
			.where(eq(encryptionIdentity.userId, user.id))
			.for('update');
		if (!identity) {
			const initial = setup.parse(body);
			await tx.insert(encryptionIdentity).values({ userId: user.id, ...initial });
		}
		await tx.insert(accountEnvelope).values({ ...data, userId: user.id });
	});
	return json({ success: true });
};

export const POST = jsonEndpoint(post);
