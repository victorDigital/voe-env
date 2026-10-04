import { and, eq, inArray, sql } from 'drizzle-orm';
import { encryptionDevice, organizationEnvelope, workspace, session } from './db/schema';
import type { Transaction } from './vault-access';
export async function revokeDevices(
	tx: Transaction,
	devices: { id: string; sessionId: string | null }[]
) {
	if (!devices.length) return;
	const recipients = devices.map((d) => `device:${d.id}`);
	const envelopes = await tx
		.select()
		.from(organizationEnvelope)
		.where(inArray(organizationEnvelope.recipient, recipients));
	for (const orgId of [...new Set(envelopes.map((e) => e.organizationId))].sort()) {
		await tx.select().from(workspace).where(eq(workspace.organizationId, orgId)).for('update');
		await tx
			.update(workspace)
			.set({ rotationRequired: true, revision: sql`${workspace.revision}+1` })
			.where(eq(workspace.organizationId, orgId));
	}
	await tx.delete(organizationEnvelope).where(inArray(organizationEnvelope.recipient, recipients));
	await tx
		.update(encryptionDevice)
		.set({ revoked: true })
		.where(
			inArray(
				encryptionDevice.id,
				devices.map((d) => d.id)
			)
		);
	const sessions = devices.flatMap((d) => (d.sessionId ? [d.sessionId] : []));
	if (sessions.length) await tx.delete(session).where(inArray(session.id, sessions));
}
