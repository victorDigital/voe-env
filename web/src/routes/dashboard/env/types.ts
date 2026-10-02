export type EnvItem = {
	name: string;
	type: 'folder' | 'key';
	value?: string;
	encrypted?: string;
	isShared?: boolean;
	sharedBy?: { email: string; name: string };
	permission?: 'read' | 'readwrite';
};
