import { getContext, setContext, onMount } from 'svelte';
import type { HotkeyAction } from './types.ts';
import { activeOverlay, isEditable, matchesKeyEvent, parseKeys } from './utils.ts';

const key = Symbol('hotkeys');
const helpKeys = parseKeys('?');
type RegisteredHotkey = HotkeyAction & { binding: ReturnType<typeof parseKeys> };

export class HotkeyManager {
	registry = $state<Record<string, RegisteredHotkey[]>>({});
	helpOpen = $state(false);
	mac = $state(false);
	activeHotkeys = $derived(
		Object.values(this.registry)
			.flat()
			.filter((action) => action.enabled?.() !== false)
	);
	#counter = 0;

	register(componentId: string, actions: HotkeyAction[]) {
		const id = `${componentId}:${++this.#counter}`;
		this.registry[id] = actions.map((action) => ({ ...action, binding: parseKeys(action.keys) }));
		return () => {
			delete this.registry[id];
		};
	}

	attach() {
		this.mac = /Mac|iPhone|iPad/.test(navigator.platform);
		let timer: ReturnType<typeof setTimeout> | undefined;
		let heldHelp = false;
		const reset = () => {
			clearTimeout(timer);
			timer = undefined;
			if (heldHelp) this.helpOpen = false;
			heldHelp = false;
		};
		const keydown = (event: KeyboardEvent) => {
			if (event.key !== 'Alt') reset();
			if (
				event.defaultPrevented ||
				event.repeat ||
				event.isComposing ||
				event.getModifierState('AltGraph')
			)
				return;
			const editing = isEditable(event);
			const overlay = activeOverlay();
			if (
				event.key === 'Alt' &&
				!event.ctrlKey &&
				!event.metaKey &&
				!event.shiftKey &&
				!editing &&
				!overlay &&
				this.activeHotkeys.length
			) {
				timer = setTimeout(() => {
					if (
						!activeOverlay() &&
						!document.activeElement?.matches('input, textarea, select, [contenteditable]')
					) {
						heldHelp = true;
						this.helpOpen = true;
					}
				}, 300);
				return;
			}
			if (
				!editing &&
				!overlay &&
				this.activeHotkeys.length &&
				matchesKeyEvent(helpKeys, event, this.mac)
			) {
				event.preventDefault();
				this.helpOpen = true;
				return;
			}
			for (const action of this.activeHotkeys) {
				if (editing && !action.allowInInput) continue;
				if (!matchesKeyEvent(action.binding, event, this.mac)) continue;
				const element = action.element?.();
				if (
					action.element &&
					(!element?.isConnected ||
						!element.getClientRects().length ||
						element.closest('[inert], [hidden], [aria-hidden="true"]'))
				)
					continue;
				if (overlay && (!element || !overlay.contains(element))) continue;
				event.preventDefault();
				action.handler();
				break;
			}
		};
		const keyup = (event: KeyboardEvent) => {
			if (event.key === 'Alt') reset();
		};
		const visibility = () => {
			if (document.hidden) reset();
		};
		window.addEventListener('keydown', keydown);
		window.addEventListener('keyup', keyup);
		window.addEventListener('blur', reset);
		document.addEventListener('visibilitychange', visibility);
		return () => {
			reset();
			window.removeEventListener('keydown', keydown);
			window.removeEventListener('keyup', keyup);
			window.removeEventListener('blur', reset);
			document.removeEventListener('visibilitychange', visibility);
		};
	}
}

export function createHotkeyManager() {
	const manager = setContext(key, new HotkeyManager());
	onMount(() => manager.attach());
	return manager;
}

export const getHotkeyManager = () => getContext<HotkeyManager | undefined>(key);

export function useHotkeys(componentId: string | (() => string), actions: () => HotkeyAction[]) {
	const manager = getHotkeyManager();
	$effect(() => {
		const current = actions();
		if (manager && current.length)
			return manager.register(
				typeof componentId === 'function' ? componentId() : componentId,
				current
			);
	});
}
