import { jsonEndpoint, readJson } from '#lib/server/json-endpoint.ts';
import { error, json } from '@sveltejs/kit';
import { eq, and } from 'drizzle-orm';
import { createHash } from 'node:crypto';
import { db } from '#lib/server/db/index.ts';
import {
	envVault,
	folderShares,
	legacyMigration,
	member,
	workspace,
	vaultSecret,
	vaultFolder,
	invitation
} from '#lib/server/db/schema.ts';
import { authenticated, authorize, lockWorkspace } from '#lib/server/vault-access.ts';
import type { RequestHandler } from './$types';
const digest = (rows: { id: string; encryptedValue: string; fullKey: string }[]) =>
	createHash('sha256')
		.update(
			JSON.stringify(
				rows
					.map((r) => [r.id, r.fullKey, r.encryptedValue])
					.sort((a, b) => a[0].localeCompare(b[0]))
			)
		)
		.digest('hex');
export const GET: RequestHandler = async (event) => {
	const { user } = authenticated(event);
	const rows = await db.select().from(envVault).where(eq(envVault.userId, user.id));
	const shares = await db
		.select({
			folderPath: folderShares.folderPath,
			sharedWithId: folderShares.sharedWithId,
			permission: folderShares.permission,
			expiresAt: folderShares.expiresAt
		})
		.from(folderShares)
		.where(eq(folderShares.ownerId, user.id));
	const [migration] = await db
		.select()
		.from(legacyMigration)
		.where(eq(legacyMigration.userId, user.id));
	return json(
		{ rows, shares, digest: digest(rows), migration: migration || null },
		{ headers: { 'Cache-Control': 'no-store' } }
	);
};
const post: RequestHandler = async (event) => {
	const { user } = authenticated(event);
	const body = await readJson(event.request);
	return db.transaction(async (tx) => {
		await lockWorkspace(tx, body.organizationId);
		const actor = await authorize(event, body.organizationId, 'provision', tx);
		if (actor.membership.role !== 'owner' || actor.state?.rotationRequired)
			error(403, 'Use your personal workspace');
		const members = await tx
			.select()
			.from(member)
			.where(eq(member.organizationId, body.organizationId));
		if (members.length !== 1)
			error(400, 'Migration destination must be a personal workspace with no other members');
		const rows = await tx.select().from(envVault).where(eq(envVault.userId, user.id));
		if (digest(rows) !== body.digest) error(409, 'Legacy source changed');
		if (body.action === 'begin') {
			const invites = await tx
				.select()
				.from(invitation)
				.where(
					and(eq(invitation.organizationId, body.organizationId), eq(invitation.status, 'pending'))
				);
			if (invites.some((i) => i.expiresAt > new Date()))
				error(409, 'Cancel outstanding invitations before migration');
			const [existing] = await tx
				.select()
				.from(legacyMigration)
				.where(eq(legacyMigration.userId, user.id));
			if (
				existing &&
				(existing.organizationId !== body.organizationId || existing.sourceDigest !== body.digest)
			)
				error(409, 'Resume the recorded migration destination');
			if (!existing)
				await tx.insert(legacyMigration).values({
					userId: user.id,
					organizationId: body.organizationId,
					sourceDigest: body.digest,
					status: 'pending'
				});
			return json({ success: true });
		}
		if (body.revision !== actor.state?.revision)
			error(409, 'Destination changed after verification. Verify again.');
		const secrets = await tx
			.select()
			.from(vaultSecret)
			.where(eq(vaultSecret.organizationId, body.organizationId));
		const folders = await tx
			.select()
			.from(vaultFolder)
			.where(eq(vaultFolder.organizationId, body.organizationId));
		const { folderPath } = await import('#lib/vault-format.ts');
		const paths = new Set(
			secrets.map((s) => [folderPath(folders, s.folderId), s.name].filter(Boolean).join(':'))
		);
		if (rows.some((r) => !paths.has(r.fullKey)) || body.verifiedCount !== rows.length)
			error(400, 'Verify every migrated secret before completing migration');
		await tx
			.insert(legacyMigration)
			.values({
				userId: user.id,
				organizationId: body.organizationId,
				sourceDigest: body.digest,
				status: 'complete',
				completedAt: new Date()
			})
			.onConflictDoUpdate({
				target: legacyMigration.userId,
				set: { status: 'complete', completedAt: new Date() }
			});
		return json({ success: true });
	});
};

export const POST = jsonEndpoint(post);
