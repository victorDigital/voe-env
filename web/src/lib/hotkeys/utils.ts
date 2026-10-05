const modifiers = new Set(['mod', 'cmd', 'ctrl', 'meta', 'alt', 'shift']);
const aliases: Record<string, string> = {
	esc: 'escape',
	return: 'enter',
	space: ' ',
	plus: '+',
	up: 'arrowup',
	down: 'arrowdown',
	left: 'arrowleft',
	right: 'arrowright'
};

export function parseKeys(keys: string) {
	const parts = keys
		.toLowerCase()
		.split('+')
		.map((part) => part.trim());
	const key = aliases[parts.at(-1)!] ?? parts.at(-1)!;
	if (!key || modifiers.has(key) || parts.slice(0, -1).some((part) => !modifiers.has(part)))
		throw new Error(`Invalid shortcut: ${keys}`);
	const required = new Set(parts.slice(0, -1));
	if (key === '?') required.add('shift');
	return { key, modifiers: required };
}

export function matchesKeyEvent(
	parsed: ReturnType<typeof parseKeys>,
	event: KeyboardEvent,
	mac: boolean
) {
	const required = parsed.modifiers;
	const command = required.has('mod') || required.has('cmd');
	const key = event.key.toLowerCase();
	if (key !== parsed.key && !(key === '?' && parsed.key === '/' && required.has('shift')))
		return false;
	return (
		event.metaKey === (required.has('meta') || (command && mac)) &&
		event.ctrlKey === (required.has('ctrl') || (command && !mac)) &&
		event.altKey === required.has('alt') &&
		event.shiftKey === required.has('shift')
	);
}

export function formatKeys(keys: string, mac: boolean) {
	const parsed = parseKeys(keys);
	const labels: Record<string, string> = {
		ctrl: mac ? '⌃' : 'Ctrl',
		mod: mac ? '⌘' : 'Ctrl',
		cmd: mac ? '⌘' : 'Ctrl',
		meta: mac ? '⌘' : 'Meta',
		alt: mac ? '⌥' : 'Alt',
		shift: mac ? '⇧' : 'Shift',
		enter: 'Enter',
		escape: 'Esc',
		' ': 'Space',
		arrowup: '↑',
		arrowdown: '↓',
		arrowleft: '←',
		arrowright: '→'
	};
	const parts = ['ctrl', 'mod', 'cmd', 'meta', 'alt', 'shift']
		.filter(
			(modifier) => parsed.modifiers.has(modifier) && !(parsed.key === '?' && modifier === 'shift')
		)
		.map((modifier) => labels[modifier]);
	parts.push(labels[parsed.key] ?? parsed.key.toUpperCase());
	return parts.join(' ');
}

export function ariaKeys(keys: string, mac: boolean) {
	const parsed = parseKeys(keys);
	const names: Record<string, string> = {
		mod: mac ? 'Meta' : 'Control',
		cmd: mac ? 'Meta' : 'Control',
		ctrl: 'Control',
		meta: 'Meta',
		alt: 'Alt',
		shift: 'Shift'
	};
	return [...parsed.modifiers]
		.map((modifier) => names[modifier])
		.concat(parsed.key === ' ' ? 'Space' : parsed.key)
		.join('+');
}

export function isEditable(event: KeyboardEvent) {
	return event
		.composedPath()
		.some(
			(node) =>
				node instanceof HTMLElement &&
				(node.isContentEditable ||
					node.matches('input, textarea, select, [role="textbox"], [role="combobox"]'))
		);
}

export function activeOverlay() {
	return Array.from(
		document.querySelectorAll<HTMLElement>(
			'[role="dialog"], [role="alertdialog"], [role="menu"], [role="listbox"]'
		)
	)
		.reverse()
		.find(
			(element) =>
				element.dataset.state !== 'closed' &&
				element.getAttribute('aria-hidden') !== 'true' &&
				element.getClientRects().length
		);
}
