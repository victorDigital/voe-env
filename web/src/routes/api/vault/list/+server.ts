import { json } from '@sveltejs/kit';
import { auth } from '$lib/server/auth';
import { getAllEnv } from '$lib/server/env-vault';
import type { RequestHandler } from './$types';

interface TreeNode {
	type: 'folder' | 'key';
	children: Map<string, TreeNode>;
}

interface TreeEntry {
	type: 'folder' | 'key';
	name: string;
	children?: TreeEntry[];
}

export const GET: RequestHandler = async ({ request }) => {
	// Get session using bearer token from Authorization header
	const session = await auth.api.getSession({
		headers: request.headers
	});

	if (!session || !session.user) {
		return json({ error: 'Unauthorized' }, { status: 401 });
	}

	try {
		const userId = session.user.id;

		// Get all environment variables for this user
		const allEnvs = await getAllEnv(userId);
		const keys = Object.keys(allEnvs);

		// Build tree structure
		const root = new Map<string, TreeNode>();

		for (const fullKey of keys) {
			const parts = fullKey.split(':');
			let current = root;

			for (let i = 0; i < parts.length; i++) {
				const part = parts[i];
				const isLast = i === parts.length - 1;
				const type = isLast ? 'key' : 'folder';

				if (!current.has(part)) {
					current.set(part, {
						type,
						children: new Map()
					});
				}

				const node = current.get(part)!;
				// If this part was previously a key but now we found it has children,
				// upgrade it to a folder
				if (!isLast && node.type === 'key') {
					node.type = 'folder';
				}

				current = node.children;
			}
		}

		// Convert to serializable format
		function buildTree(map: Map<string, TreeNode>): TreeEntry[] {
			const entries: TreeEntry[] = [];
			for (const [name, node] of map) {
				const entry: TreeEntry = {
					type: node.type,
					name
				};
				if (node.children.size > 0) {
					entry.children = buildTree(node.children);
				}
				entries.push(entry);
			}
			// Sort: folders first, then alphabetically
			entries.sort((a, b) => {
				if (a.type === 'folder' && b.type === 'key') return -1;
				if (a.type === 'key' && b.type === 'folder') return 1;
				return a.name.localeCompare(b.name);
			});
			return entries;
		}

		const tree = buildTree(root);

		return json({
			success: true,
			tree,
			count: keys.length
		});
	} catch (error: any) {
		return json({ error: error.message || 'Internal server error' }, { status: 500 });
	}
};
