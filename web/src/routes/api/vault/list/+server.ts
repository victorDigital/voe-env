import { json } from '@sveltejs/kit';
import { auth } from '$lib/server/auth';
import { getAllEnv } from '$lib/server/env-vault';
import { getIncomingShares } from '$lib/server/shares';
import { getSharedVaultEnv } from '$lib/server/env-vault';
import type { RequestHandler } from './$types';

interface TreeNode {
	type: 'folder' | 'key';
	children: Map<string, TreeNode>;
	isShared?: boolean;
	sharedBy?: { email: string; name: string };
	permission?: 'read' | 'readwrite';
	vaultPassword?: string;
}

interface TreeEntry {
	type: 'folder' | 'key';
	name: string;
	children?: TreeEntry[];
	isShared?: boolean;
	sharedBy?: { email: string; name: string };
	permission?: 'read' | 'readwrite';
	vaultPassword?: string;
}

export const GET: RequestHandler = async ({ request }) => {
	const session = await auth.api.getSession({
		headers: request.headers
	});

	if (!session || !session.user) {
		return json({ error: 'Unauthorized' }, { status: 401 });
	}

	try {
		const userId = session.user.id;

		// Get user's own environment variables
		const allEnvs = await getAllEnv(userId);
		const ownKeys = Object.keys(allEnvs);

		// Build tree structure for own keys
		const root = new Map<string, TreeNode>();

		for (const fullKey of ownKeys) {
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
				if (!isLast && node.type === 'key') {
					node.type = 'folder';
				}

				current = node.children;
			}
		}

		// Get shared folders
		const incomingShares = await getIncomingShares(userId);

		// Add shared folders to tree
		for (const share of incomingShares) {
			const parts = share.folderPath.split(':');
			let current = root;

			for (let i = 0; i < parts.length; i++) {
				const part = parts[i];
				const isLast = i === parts.length - 1;
				const type = isLast ? 'folder' : 'folder'; // Shares are always folders

				if (!current.has(part)) {
					current.set(part, {
						type,
						children: new Map(),
						isShared: isLast ? true : undefined,
						sharedBy: isLast ? share.owner : undefined,
						permission: isLast ? share.permission : undefined,
						vaultPassword: isLast ? share.vaultPassword : undefined
					});
				} else if (isLast) {
					// Mark existing folder as also being shared
					const node = current.get(part)!;
					node.isShared = true;
					node.sharedBy = share.owner;
					node.permission = share.permission;
					node.vaultPassword = share.vaultPassword;
				}

				current = current.get(part)!.children;
			}
		}

		// Convert to serializable format
		function buildTree(map: Map<string, TreeNode>): TreeEntry[] {
			const entries: TreeEntry[] = [];
			for (const [name, node] of map) {
				const entry: TreeEntry = {
					type: node.type,
					name,
					isShared: node.isShared,
					sharedBy: node.sharedBy,
					permission: node.permission,
					vaultPassword: node.vaultPassword
				};
				if (node.children.size > 0) {
					entry.children = buildTree(node.children);
				}
				entries.push(entry);
			}
			// Sort: folders first, then alphabetically, own folders before shared
			entries.sort((a, b) => {
				if (a.type === 'folder' && b.type === 'key') return -1;
				if (a.type === 'key' && b.type === 'folder') return 1;
				if (!a.isShared && b.isShared) return -1;
				if (a.isShared && !b.isShared) return 1;
				return a.name.localeCompare(b.name);
			});
			return entries;
		}

		const tree = buildTree(root);

		return json({
			success: true,
			tree,
			count: ownKeys.length,
			sharedCount: incomingShares.length
		});
	} catch (error: any) {
		console.error('List vault error:', error);
		return json({ error: error.message || 'Internal server error' }, { status: 500 });
	}
};
