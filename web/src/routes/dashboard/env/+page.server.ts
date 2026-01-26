import { redirect } from '@sveltejs/kit';
import { listEnv, setEnv, getEnv, deleteEnv, getAllEnv } from '$lib/server/env-vault';

export const load = async ({ locals, url }: any) => {
	// Ensure user is authenticated
	if (!locals.user || !locals.session) {
		throw redirect(302, '/');
	}

	const path = url.searchParams.get('path') || '';
	const items = await listEnv(locals.user.id, path);

	return {
		session: locals.session,
		user: locals.user,
		path,
		items,
		encryptedEnvs: await getAllEnv(locals.user.id)
	};
};

export const actions: any = {
	set: async ({ request, locals }: any) => {
		if (!locals.user) throw redirect(302, '/');

		const data = await request.formData();
		const key = data.get('key') as string;
		const encryptedValue = data.get('encryptedValue') as string;
		const path = data.get('path') as string;

		if (!key || !encryptedValue) {
			return { success: false, error: 'Key and encrypted value required' };
		}

		const fullKey = path ? `${path}:${key}` : key;

		try {
			await setEnv(locals.user.id, fullKey, encryptedValue);
			return { success: true, action: 'set' };
		} catch (error) {
			return { success: false, error: 'Failed to set env', action: 'set' };
		}
	},

	get: async ({ request, locals }: any) => {
		if (!locals.user) throw redirect(302, '/');

		const data = await request.formData();
		const fullKey = data.get('fullKey') as string;

		if (!fullKey) {
			return { success: false, error: 'Key required' };
		}

		try {
			const encryptedValue = await getEnv(locals.user.id, fullKey);
			return { success: true, encryptedValue, action: 'get' };
		} catch (error: any) {
			return { success: false, error: error.message, action: 'get' };
		}
	},

	delete: async ({ request, locals }: any) => {
		if (!locals.user) throw redirect(302, '/');

		const data = await request.formData();
		const fullKey = data.get('fullKey') as string;

		if (!fullKey) {
			return { success: false, error: 'Key required' };
		}

		try {
			await deleteEnv(locals.user.id, fullKey);
			return { success: true, action: 'delete' };
		} catch (error) {
			return { success: false, error: 'Failed to delete env', action: 'delete' };
		}
	}
};
