import { error, type RequestEvent } from '@sveltejs/kit';
import { and, eq } from 'drizzle-orm';
import { db } from './db';
import { encryptionDevice, member, organizationEnvelope, workspace } from './db/schema';
import { permits } from '../permissions';
import { recentlyVerified } from './recent-verification';
export type Transaction = Parameters<Parameters<typeof db.transaction>[0]>[0];
export function authenticated(event: RequestEvent) {
	if (!event.locals.user || !event.locals.session) error(401, 'Sign in first');
	return { user: event.locals.user, session: event.locals.session };
}
export async function principal(event: RequestEvent, tx: Transaction | typeof db = db) {
	const auth = authenticated(event);
	const [device] = await tx
		.select()
		.from(encryptionDevice)
		.where(eq(encryptionDevice.sessionId, auth.session.id));
	if (event.request.headers.has('authorization') && !device)
		error(403, 'Enroll this CLI with ve auth');
	if (device?.revoked) error(403, 'Device access was revoked');
	return { ...auth, device, recipient: device ? `device:${device.id}` : `user:${auth.user.id}` };
}
export async function authorize(
	event: RequestEvent,
	organizationId: string,
	action: 'read' | 'write' | 'provision',
	tx: Transaction | typeof db = db
) {
	const actor = await principal(event, tx);
	const [membership] = await tx
		.select()
		.from(member)
		.where(and(eq(member.organizationId, organizationId), eq(member.userId, actor.user.id)));
	if (!membership || !permits(membership.role, action)) error(403, 'Workspace access denied');
	const [state] = await tx
		.select()
		.from(workspace)
		.where(eq(workspace.organizationId, organizationId));
	if (state && action !== 'read') {
		const [own] = await tx
			.select()
			.from(organizationEnvelope)
			.where(
				and(
					eq(organizationEnvelope.organizationId, organizationId),
					eq(organizationEnvelope.recipient, actor.recipient)
				)
			);
		if (!own || own.epoch !== state.epoch)
			error(403, 'Your encryption identity must be approved before managing this workspace');
	}
	if (
		!actor.device &&
		action === 'write' &&
		!(await recentlyVerified(actor.session.id, actor.user.id, false, Infinity))
	)
		error(403, 'Unlock with an enrolled passkey or recovery key before editing this workspace');
	if (actor.device) {
		const [envelope] = await tx
			.select()
			.from(organizationEnvelope)
			.where(
				and(
					eq(organizationEnvelope.organizationId, organizationId),
					eq(organizationEnvelope.recipient, actor.recipient)
				)
			);
		if (!envelope || envelope.epoch !== state?.epoch)
			error(403, 'This device has not been approved for this workspace');
		if (action === 'provision') error(403, 'Use your browser to manage workspace access');
	}
	return { ...actor, membership, state };
}
export async function lockWorkspace(tx: Transaction, organizationId: string) {
	await tx
		.select()
		.from(workspace)
		.where(eq(workspace.organizationId, organizationId))
		.for('update');
}
