<script lang="ts">
	import { MediaQuery } from 'svelte/reactivity';
	import { cn } from '#lib/utils.ts';
	import { getHotkeyManager } from './manager.svelte.ts';
	import { formatKeys } from './utils.ts';
	let {
		keys,
		class: className,
		ariaHidden = false,
		hideOnTouch = false
	}: { keys: string; class?: string; ariaHidden?: boolean; hideOnTouch?: boolean } = $props();
	const manager = getHotkeyManager();
	const hasKeyboard = new MediaQuery('(pointer: fine) and (hover: hover)', true);
</script>

{#if !hideOnTouch || hasKeyboard.current}
	<kbd
		aria-hidden={ariaHidden || undefined}
		class={cn(
			'shrink-0 border border-border bg-muted/30 px-1 py-0.5 font-mono text-[10px] leading-none text-muted-foreground',
			className
		)}>{formatKeys(keys, manager?.mac ?? false)}</kbd
	>
{/if}
