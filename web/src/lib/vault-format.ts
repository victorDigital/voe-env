export type Folder = { id: string; parentId: string | null; name: string; wrappedKey: string };
export type Secret = { id: string; folderId: string; name: string; encryptedValue: string };
export type Envelope = { recipient: string; wrappedKey: string; identityBinding: string };
export type WorkspaceSnapshot = {
	organizationId: string;
	epoch: number;
	revision: number;
	rotationRequired: boolean;
	role: string;
	folders: Folder[];
	secrets: Secret[];
	envelopes: Envelope[];
};
export const context = (...parts: (string | number)[]) => JSON.stringify(['voe', 1, ...parts]);
export const secretContext = (
	org: string,
	folder: string,
	id: string,
	name: string,
	epoch: number
) => context('secret', org, folder, id, name, epoch);
export const folderContext = (org: string, id: string, epoch: number) =>
	context('folder', org, id, epoch);
export const orgContext = (org: string, recipient: string, epoch: number) =>
	context('organization', org, recipient, epoch);
export function folderPath(folders: Folder[], id: string): string {
	const folder = folders.find((f) => f.id === id);
	if (!folder) throw new Error('Folder not found');
	return folder.parentId
		? [folderPath(folders, folder.parentId), folder.name].filter(Boolean).join(':')
		: '';
}
