import { createAccessControl } from 'better-auth/plugins/access';
import {
	defaultStatements,
	ownerAc,
	adminAc,
	memberAc
} from 'better-auth/plugins/organization/access';
export const ac = createAccessControl({
	...defaultStatements,
	vault: ['read', 'write', 'provision'] as const
});
export const roles = {
	owner: ac.newRole({ ...ownerAc.statements, vault: ['read', 'write', 'provision'] }),
	admin: ac.newRole({ ...adminAc.statements, vault: ['read', 'write', 'provision'] }),
	member: ac.newRole({ ...memberAc.statements, vault: ['read', 'write'] }),
	viewer: ac.newRole({ vault: ['read'] })
};
export type Role = keyof typeof roles;
export function permits(role: string, action: 'read' | 'write' | 'provision'): boolean {
	return Object.hasOwn(roles, role) && roles[role as Role].authorize({ vault: [action] }).success;
}
