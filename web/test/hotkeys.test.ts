import { describe, expect, test } from 'bun:test';
import { ariaKeys, formatKeys, matchesKeyEvent, parseKeys } from '../src/lib/hotkeys/utils.ts';

function event(key: string, modifiers: Partial<KeyboardEvent> = {}) {
	return {
		key,
		metaKey: false,
		ctrlKey: false,
		shiftKey: false,
		altKey: false,
		...modifiers
	} as KeyboardEvent;
}

describe('keyboard shortcuts', () => {
	test('submit and navigation use the platform command modifier', () => {
		for (const [keys, key] of [
			['mod+enter', 'Enter'],
			['cmd+b', 'b']
		]) {
			const shortcut = parseKeys(keys);
			expect(matchesKeyEvent(shortcut, event(key, { metaKey: true }), true)).toBe(true);
			expect(matchesKeyEvent(shortcut, event(key, { ctrlKey: true }), false)).toBe(true);
			expect(matchesKeyEvent(shortcut, event(key, { ctrlKey: true }), true)).toBe(false);
			expect(matchesKeyEvent(shortcut, event(key, { metaKey: true }), false)).toBe(false);
		}
	});
	test('letter shortcuts do not consume browser commands or modified input', () => {
		const add = parseKeys('n');
		expect(matchesKeyEvent(add, event('n'), true)).toBe(true);
		for (const modifier of ['metaKey', 'ctrlKey', 'shiftKey', 'altKey']) {
			expect(matchesKeyEvent(add, event('n', { [modifier]: true }), true)).toBe(false);
		}
		expect(matchesKeyEvent(parseKeys('shift+n'), event('N', { shiftKey: true }), true)).toBe(true);
	});
	test('help and parent folder match punctuation and named keys', () => {
		expect(matchesKeyEvent(parseKeys('?'), event('?', { shiftKey: true }), true)).toBe(true);
		expect(matchesKeyEvent(parseKeys('/'), event('?', { shiftKey: true }), true)).toBe(false);
		expect(matchesKeyEvent(parseKeys('alt+up'), event('ArrowUp', { altKey: true }), false)).toBe(
			true
		);
		expect(matchesKeyEvent(parseKeys('mod+return'), event('Enter', { metaKey: true }), true)).toBe(
			true
		);
	});
	test('display hints and accessible names agree across platforms', () => {
		expect(formatKeys('mod+enter', true)).toBe('⌘ Enter');
		expect(ariaKeys('mod+enter', true)).toBe('Meta+enter');
		expect(formatKeys('mod+enter', false)).toBe('Ctrl Enter');
		expect(ariaKeys('mod+enter', false)).toBe('Control+enter');
		expect(formatKeys('?', true)).toBe('?');
		expect(formatKeys('alt+up', true)).toBe('⌥ ↑');
		expect(() => parseKeys('shift')).toThrow('Invalid shortcut');
		expect(() => parseKeys('unknown+n')).toThrow('Invalid shortcut');
	});
});
