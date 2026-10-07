<script lang="ts">
	import { untrack } from 'svelte';
	import { estimateSecretLength } from '#lib/vault-crypto.ts';

	let {
		encryptedValue,
		value,
		revealed,
		animate = true
	}: {
		encryptedValue: string;
		value: string | undefined;
		revealed: boolean;
		animate?: boolean;
	} = $props();
	let masked = $derived('•'.repeat(estimateSecretLength(encryptedValue) ?? 12));
	let shown = $derived(revealed && value !== undefined);
	let text = $derived(shown ? value! : masked);
	let display: HTMLSpanElement;
	let previousShown: boolean | undefined;
	const glyphs = '0123456789ABCDEF#$%&*+=?';

	$effect(() => {
		const target = text;
		const revealing = shown;
		const changed = previousShown !== undefined && previousShown !== revealing;
		previousShown = revealing;
		if (
			!changed ||
			!untrack(() => animate) ||
			value === undefined ||
			window.matchMedia('(prefers-reduced-motion: reduce)').matches
		) {
			display.textContent = target;
			return;
		}
		const characters = Array.from(target).slice(0, Math.ceil(display.clientWidth / 7) + 1);
		const start = performance.now();
		let frame = 0;
		let lastStep = -1;
		function tick(now: number) {
			const progress = Math.min((now - start) / 240, 1);
			if (progress === 1) {
				display.textContent = target;
				return;
			}
			const step = Math.floor(progress * 8);
			if (step !== lastStep) {
				lastStep = step;
				display.textContent = characters
					.map((character, index) => {
						const position = index / Math.max(characters.length - 1, 1);
						const settled = revealing ? position < progress : position > 1 - progress;
						return settled ? character : glyphs[Math.floor(Math.random() * glyphs.length)];
					})
					.join('');
			}
			frame = requestAnimationFrame(tick);
		}
		tick(start);
		return () => cancelAnimationFrame(frame);
	});
</script>

<code class="block min-w-0 text-xs text-muted-foreground">
	<span class="block truncate" aria-hidden="true" bind:this={display}></span>
	<span class="sr-only">{shown ? `Secret value: ${value}` : 'Hidden value'}</span>
</code>
