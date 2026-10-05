import { revokeDevices } from '#lib/server/device-revocation.ts';
import { jsonEndpoint, readJson } from '#lib/server/json-endpoint.ts';
import { error, json } from '@sveltejs/kit';
import { and, eq, inArray, sql } from 'drizzle-orm';
import { z } from 'zod';
import { db } from '#lib/server/db/index.ts';
import {
	deviceCode,
	encryptionDevice,
	organizationEnvelope,
	workspace
} from '#lib/server/db/schema.ts';
import { authenticated, authorize, lockWorkspace } from '#lib/server/vault-access.ts';
import { recentlyVerified } from '#lib/server/recent-verification.ts';
import { id, publicKey, rsaEnvelope, aesEnvelope } from '#lib/server/vault-validation.ts';
import type { RequestHandler } from './$types';
export const GET: RequestHandler = async (event) => {
	const { user } = authenticated(event);
	const code = event.url.searchParams.get('code');
	if (!code)
		return json(
			await db
				.select({
					id: encryptionDevice.id,
					publicKey: encryptionDevice.publicKey,
					revoked: encryptionDevice.revoked,
					createdAt: encryptionDevice.createdAt,
					lastUsedAt: encryptionDevice.lastUsedAt
				})
				.from(encryptionDevice)
				.where(eq(encryptionDevice.userId, user.id))
		);
	const [enrollment] = await db
		.select({
			id: encryptionDevice.id,
			publicKey: encryptionDevice.publicKey,
			expiresAt: deviceCode.expiresAt,
			status: deviceCode.status,
			userId: deviceCode.userId
		})
		.from(encryptionDevice)
		.innerJoin(deviceCode, eq(encryptionDevice.deviceCodeId, deviceCode.id))
		.where(eq(deviceCode.userCode, code));
	if (
		!enrollment ||
		enrollment.userId !== user.id ||
		enrollment.status !== 'pending' ||
		enrollment.expiresAt < new Date()
	)
		error(404, 'Pending CLI enrollment not found. Update the CLI and run ve auth.');
	return json(enrollment, { headers: { 'Cache-Control': 'no-store' } });
};
const post: RequestHandler = async (event) => {
	const body = await readJson(event.request);
	if (body.action === 'enroll') {
		const data = z.object({ deviceCode: z.string().min(20).max(256), publicKey }).parse(body);
		return db.transaction(async (tx) => {
			const [code] = await tx
				.select()
				.from(deviceCode)
				.where(eq(deviceCode.deviceCode, data.deviceCode))
				.for('update');
			if (
				!code ||
				code.status !== 'pending' ||
				code.expiresAt < new Date() ||
				code.clientId !== 'voe-cli'
			)
				error(400, 'Invalid device request');
			const deviceId = crypto.randomUUID();
			await tx
				.insert(encryptionDevice)
				.values({ id: deviceId, deviceCodeId: code.id, publicKey: data.publicKey });
			return json({ id: deviceId });
		});
	}
	const { user, session } = authenticated(event);
	if (!(await recentlyVerified(session.id, user.id))) error(403, 'Unlock with your passkey first');
	if (body.action === 'revoke') {
		const deviceId = id.parse(body.deviceId);
		await db.transaction(async (tx) => {
			const [device] = await tx
				.select()
				.from(encryptionDevice)
				.where(and(eq(encryptionDevice.id, deviceId), eq(encryptionDevice.userId, user.id)))
				.for('update');
			if (!device) error(404, 'Device not found');
			await revokeDevices(tx, [device]);
		});
		return json({ success: true });
	}
	const data = z
		.object({
			deviceId: id,
			publicKey,
			envelopes: z
				.array(
					z.object({
						organizationId: id,
						epoch: z.number().int(),
						wrappedKey: rsaEnvelope,
						identityBinding: aesEnvelope
					})
				)
				.min(1)
				.max(100)
		})
		.parse(body);
	return db.transaction(async (tx) => {
		const [device] = await tx
			.select()
			.from(encryptionDevice)
			.where(eq(encryptionDevice.id, data.deviceId))
			.for('update');
		if (!device || device.publicKey !== data.publicKey || device.userId)
			error(409, 'Device enrollment changed or has already been approved');
		const [code] = await tx
			.select()
			.from(deviceCode)
			.where(eq(deviceCode.id, device.deviceCodeId))
			.for('update');
		if (
			!code ||
			code.userId !== user.id ||
			code.status !== 'pending' ||
			code.expiresAt < new Date()
		)
			error(403, 'Device request no longer available');
		for (const envelope of data.envelopes.sort((a, b) =>
			a.organizationId.localeCompare(b.organizationId)
		)) {
			await lockWorkspace(tx, envelope.organizationId);
			const actor = await authorize(event, envelope.organizationId, 'read', tx);
			if (!actor.state || actor.state.rotationRequired || actor.state.epoch !== envelope.epoch)
				error(409, 'Workspace key changed');
			const [own] = await tx
				.select()
				.from(organizationEnvelope)
				.where(
					and(
						eq(organizationEnvelope.organizationId, envelope.organizationId),
						eq(organizationEnvelope.recipient, `user:${user.id}`)
					)
				);
			if (!own) error(403, 'Your encryption access has not been provisioned');
			await tx
				.insert(organizationEnvelope)
				.values({ ...envelope, recipient: `device:${device.id}`, provisionedBy: user.id });
			await tx
				.update(workspace)
				.set({ revision: sql`${workspace.revision}+1` })
				.where(eq(workspace.organizationId, envelope.organizationId));
		}
		await tx
			.update(encryptionDevice)
			.set({ userId: user.id })
			.where(eq(encryptionDevice.id, device.id));
		return json({ success: true });
	});
};

export const POST = jsonEndpoint(post);
