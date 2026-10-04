import { json } from '@sveltejs/kit';
import { eq } from 'drizzle-orm';
import { db } from '#lib/server/db/index.ts';
import { member, organization } from '#lib/server/db/schema.ts';
import { authenticated } from '#lib/server/vault-access.ts';
import type { RequestHandler } from './$types';
export const GET: RequestHandler = async (event) => {
	const { user } = authenticated(event);
	return json(
		await db
			.select({ id: organization.id, name: organization.name, role: member.role })
			.from(member)
			.innerJoin(organization, eq(member.organizationId, organization.id))
			.where(eq(member.userId, user.id)),
		{ headers: { 'Cache-Control': 'no-store' } }
	);
};
