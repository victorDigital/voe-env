import { jsonEndpoint, readJson } from '#lib/server/json-endpoint.ts';
import { error, json } from '@sveltejs/kit';
import { and, eq, inArray, sql } from 'drizzle-orm';
import { z } from 'zod';
import { db } from '#lib/server/db/index.ts';
import {
	workspace,
	member,
	organization,
	vaultFolder,
	vaultSecret,
	organizationEnvelope,
	encryptionIdentity,
	encryptionDevice,
	user,
	auditEvent
} from '#lib/server/db/schema.ts';
import { authorize, lockWorkspace } from '#lib/server/vault-access.ts';
import { recentlyVerified } from '#lib/server/recent-verification.ts';
import { snapshotSchema, envelopeSchema, validateTree, id } from '#lib/server/vault-validation.ts';
import type { RequestHandler } from './$types';
async function recipients(
	organizationId: string,
	tx: typeof db | Parameters<Parameters<typeof db.transaction>[0]>[0] = db
) {
	const members = await tx
		.select({
			userId: member.userId,
			name: user.name,
			email: user.email,
			role: member.role,
			publicKey: encryptionIdentity.publicKey
		})
		.from(member)
		.innerJoin(user, eq(user.id, member.userId))
		.leftJoin(encryptionIdentity, eq(encryptionIdentity.userId, member.userId))
		.where(eq(member.organizationId, organizationId));
	const devices = members.length
		? await tx
				.select({
					id: encryptionDevice.id,
					userId: encryptionDevice.userId,
					publicKey: encryptionDevice.publicKey,
					lastUsedAt: encryptionDevice.lastUsedAt
				})
				.from(encryptionDevice)
				.where(
					and(
						inArray(
							encryptionDevice.userId,
							members.map((m) => m.userId)
						),
						eq(encryptionDevice.revoked, false)
					)
				)
		: [];
	return { members, devices };
}
export const GET: RequestHandler = async (event) => {
	const org = event.params.id;
	return db.transaction(async (tx) => {
		await lockWorkspace(tx, org);
		const actor = await authorize(event, org, 'read', tx);
		const envelopes = await tx
			.select()
			.from(organizationEnvelope)
			.where(
				and(
					eq(organizationEnvelope.organizationId, org),
					eq(organizationEnvelope.recipient, actor.recipient)
				)
			);
		const folders = actor.state
			? await tx.select().from(vaultFolder).where(eq(vaultFolder.organizationId, org))
			: [];
		const secrets = actor.state
			? await tx.select().from(vaultSecret).where(eq(vaultSecret.organizationId, org))
			: [];
		const recipientRows = await tx
			.select({
				recipient: organizationEnvelope.recipient,
				identityBinding: organizationEnvelope.identityBinding
			})
			.from(organizationEnvelope)
			.where(eq(organizationEnvelope.organizationId, org));
		const directory = actor.device ? { members: [], devices: [] } : await recipients(org, tx);
		return json(
			{
				organizationId: org,
				epoch: actor.state?.epoch || 1,
				revision: actor.state?.revision || 0,
				rotationRequired: actor.state?.rotationRequired || false,
				role: actor.membership.role,
				folders,
				secrets,
				envelopes,
				recipients: recipientRows.map((r) => r.recipient),
				bindings: recipientRows,
				...directory
			},
			{ headers: { 'Cache-Control': 'no-store' } }
		);
	});
};
const post: RequestHandler = async (event) => {
	const org = event.params.id;
	const body = await readJson(event.request);
	return db.transaction(async (tx) => {
		await tx.select().from(organization).where(eq(organization.id, org)).for('update');
		await lockWorkspace(tx, org);
		const action =
			body.action === 'save' ? 'write' : body.action === 'leave' ? 'read' : 'provision';
		const actor = await authorize(event, org, action, tx);
		if (body.action !== 'save' && !(await recentlyVerified(actor.session.id, actor.user.id)))
			error(403, 'Verify with your passkey again');
		const state = actor.state;
		if (state && body.revision !== state.revision)
			error(409, 'Workspace changed. Reload before saving.');
		if (!state && !['initialize', 'delete-workspace'].includes(body.action))
			error(409, 'Workspace encryption has not been initialized');
		const audit = async (action: string) =>
			tx
				.insert(auditEvent)
				.values({ id: crypto.randomUUID(), organizationId: org, actorId: actor.user.id, action });
		const bump = async (rotationRequired = state?.rotationRequired || false) =>
			tx
				.update(workspace)
				.set({ revision: sql`${workspace.revision}+1`, rotationRequired })
				.where(eq(workspace.organizationId, org));
		if (body.action === 'delete-workspace') {
			const [orgRow] = await tx.select().from(organization).where(eq(organization.id, org));
			if (actor.membership.role !== 'owner' || body.name !== orgRow?.name)
				error(403, 'Only an owner can delete a workspace after confirming its name');
			await tx.delete(organization).where(eq(organization.id, org));
			await tx.insert(auditEvent).values({
				id: crypto.randomUUID(),
				actorId: actor.user.id,
				action: `delete-workspace:${org}`
			});
			return json({ success: true });
		}
		if (body.action === 'leave') {
			body.userId = actor.user.id;
			body.action = 'remove-member';
		}
		if (body.action === 'remove-member' || body.action === 'role') {
			const targetId = id.parse(body.userId);
			const [target] = await tx
				.select()
				.from(member)
				.where(and(eq(member.organizationId, org), eq(member.userId, targetId)))
				.for('update');
			if (!target) error(404, 'Member not found');
			if (actor.membership.role !== 'owner' && (target.role === 'owner' || body.role === 'owner'))
				error(403, 'Only an owner can change ownership');
			const owners = await tx
				.select()
				.from(member)
				.where(and(eq(member.organizationId, org), eq(member.role, 'owner')));
			if (
				target.role === 'owner' &&
				owners.length === 1 &&
				(body.action === 'remove-member' || body.role !== 'owner')
			)
				error(400, 'Add another owner before removing the last owner');
			if (body.action === 'role') {
				const role = z.enum(['owner', 'admin', 'member', 'viewer']).parse(body.role);
				await tx.update(member).set({ role }).where(eq(member.id, target.id));
				await bump();
			} else {
				await tx.delete(member).where(eq(member.id, target.id));
				const devices = await tx
					.select()
					.from(encryptionDevice)
					.where(eq(encryptionDevice.userId, targetId));
				await tx
					.delete(organizationEnvelope)
					.where(
						and(
							eq(organizationEnvelope.organizationId, org),
							inArray(organizationEnvelope.recipient, [
								`user:${targetId}`,
								...devices.map((d) => `device:${d.id}`)
							])
						)
					);
				await bump(true);
			}
			await audit(body.action);
			return json({ success: true });
		}
		if (body.action === 'revoke-device') {
			const deviceId = id.parse(body.deviceId);
			const [device] = await tx
				.select()
				.from(encryptionDevice)
				.where(eq(encryptionDevice.id, deviceId));
			if (!device) error(404, 'Device not found');
			await tx
				.delete(organizationEnvelope)
				.where(
					and(
						eq(organizationEnvelope.organizationId, org),
						eq(organizationEnvelope.recipient, `device:${deviceId}`)
					)
				);
			await bump(true);
			await audit('revoke-device');
			return json({ success: true });
		}
		if (body.action === 'provision') {
			if (state!.rotationRequired) error(409, 'Rotate workspace keys before granting access');
			const envelope = envelopeSchema.parse(body);
			const { members, devices } = await recipients(org, tx);
			const target = envelope.recipient.startsWith('user:')
				? members.find((m) => `user:${m.userId}` === envelope.recipient)
				: devices.find((d) => `device:${d.id}` === envelope.recipient);
			if (!target?.publicKey || body.publicKey !== target.publicKey)
				error(409, 'Recipient identity changed');
			const [own] = await tx
				.select()
				.from(organizationEnvelope)
				.where(
					and(
						eq(organizationEnvelope.organizationId, org),
						eq(organizationEnvelope.recipient, actor.recipient)
					)
				);
			if (!own) error(403, 'Your encryption access has not been provisioned');
			await tx
				.insert(organizationEnvelope)
				.values({
					...envelope,
					organizationId: org,
					epoch: state!.epoch,
					provisionedBy: actor.user.id
				})
				.onConflictDoNothing();
			await bump();
			await audit('provision');
			return json({ success: true });
		}
		if (!['initialize', 'save', 'rotate'].includes(body.action)) error(400, 'Unknown operation');
		const data = snapshotSchema.parse(body);
		try {
			validateTree(data.folders, data.secrets);
		} catch (e) {
			error(400, (e as Error).message);
		}
		const initializing = body.action === 'initialize';
		const rotating = body.action === 'rotate';
		if (initializing && (state || actor.membership.role !== 'owner'))
			error(409, 'Only an owner can initialize an empty workspace');
		if (!initializing && !rotating && state!.rotationRequired)
			error(409, 'Key rotation is required before writing');
		if (data.epoch !== (initializing ? 1 : rotating ? state!.epoch + 1 : state!.epoch))
			error(409, 'Incorrect key epoch');
		if (initializing || rotating) {
			const envelopes = data.envelopes || [];
			const old = state
				? await tx
						.select()
						.from(organizationEnvelope)
						.where(eq(organizationEnvelope.organizationId, org))
				: [];
			const expected = initializing ? [actor.recipient] : old.map((e) => e.recipient);
			if (
				envelopes.length !== expected.length ||
				new Set(envelopes.map((e) => e.recipient)).size !== envelopes.length ||
				envelopes.some((e) => !expected.includes(e.recipient))
			)
				error(400, 'Provide a key envelope for every remaining recipient');
			if (initializing) await tx.insert(workspace).values({ organizationId: org });
			if (rotating) {
				const oldSecrets = await tx
					.select()
					.from(vaultSecret)
					.where(eq(vaultSecret.organizationId, org));
				const oldFolders = await tx
					.select()
					.from(vaultFolder)
					.where(eq(vaultFolder.organizationId, org));
				if (
					oldSecrets.length !== data.secrets.length ||
					oldSecrets.some(
						(s) =>
							!data.secrets.some(
								(n) =>
									n.id === s.id &&
									n.folderId === s.folderId &&
									n.name === s.name &&
									n.encryptedValue !== s.encryptedValue
							)
					) ||
					oldFolders.length !== data.folders.length ||
					oldFolders.some(
						(f) =>
							!data.folders.some(
								(n) =>
									n.id === f.id &&
									n.name === f.name &&
									n.parentId === f.parentId &&
									n.wrappedKey !== f.wrappedKey
							)
					)
				)
					error(
						400,
						'Rotation must replace every key and ciphertext without changing data structure'
					);
			}
			await tx.delete(organizationEnvelope).where(eq(organizationEnvelope.organizationId, org));
			await tx.insert(organizationEnvelope).values(
				envelopes.map((e) => ({
					...e,
					organizationId: org,
					epoch: data.epoch,
					provisionedBy: actor.user.id
				}))
			);
		}
		const existingIds = await tx
			.select()
			.from(vaultFolder)
			.where(
				inArray(
					vaultFolder.id,
					data.folders.map((f) => f.id)
				)
			);
		if (existingIds.some((f) => f.organizationId !== org)) error(400, 'Invalid folder ID');
		await tx.delete(vaultSecret).where(eq(vaultSecret.organizationId, org));
		await tx.delete(vaultFolder).where(eq(vaultFolder.organizationId, org));
		let remaining = [...data.folders];
		const inserted = new Set<string>();
		while (remaining.length) {
			const batch = remaining.filter((f) => f.parentId === null || inserted.has(f.parentId));
			await tx.insert(vaultFolder).values(batch.map((f) => ({ ...f, organizationId: org })));
			batch.forEach((f) => inserted.add(f.id));
			remaining = remaining.filter((f) => !inserted.has(f.id));
		}
		if (data.secrets.length)
			await tx.insert(vaultSecret).values(data.secrets.map((s) => ({ ...s, organizationId: org })));
		await tx
			.update(workspace)
			.set({ epoch: data.epoch, revision: (state?.revision || 0) + 1, rotationRequired: false })
			.where(eq(workspace.organizationId, org));
		await audit(body.action);
		return json({ success: true, revision: (state?.revision || 0) + 1 });
	});
};

export const POST = jsonEndpoint(post);
