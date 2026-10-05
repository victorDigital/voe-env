import { eq } from 'drizzle-orm';
import { db } from '#lib/server/db/index.ts';
import { organization, member } from '#lib/server/db/schema.ts';
import { redirect } from '@sveltejs/kit';
import type { LayoutServerLoad } from './$types';

export const load: LayoutServerLoad = async ({ locals, url, cookies }) => {
	if (!locals.user || !locals.session) {
		redirect(303, `/login?redirectTo=${encodeURIComponent(url.pathname + url.search)}`);
	}

	return {
		user: locals.user,
		workspaces: await db
			.select({ id: organization.id, name: organization.name, role: member.role })
			.from(member)
			.innerJoin(organization, eq(member.organizationId, organization.id))
			.where(eq(member.userId, locals.user.id))
			.orderBy(organization.name),
		selectedWorkspace: url.searchParams.get('workspace') || '',
		sidebarOpen: cookies.get('sidebar_state') !== 'false'
	};
};
