export type Hotkey = {
	keys: string;
	description: string;
	category?: string;
	allowInInput?: boolean;
};

export type HotkeyAction = Hotkey & {
	id: string;
	handler: () => void;
	enabled?: () => boolean;
	element?: () => HTMLElement | null;
};
