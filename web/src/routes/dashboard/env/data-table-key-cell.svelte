<script lang="ts">
	import Lock from 'remixicon-svelte/icons/lock-line';
	import Spinner from '#lib/components/ui/spinner/spinner.svelte';

	let {
		name,
		isDecrypted,
		isUnlocking
	}: {
		name: string;
		isDecrypted: boolean;
		isUnlocking: boolean;
	} = $props();
</script>

<div class="flex min-w-0 items-center gap-2.5">
	{#if isUnlocking}
		<Spinner class="size-3.5 shrink-0 text-muted-foreground" />
	{:else if !isDecrypted}
		<Lock class="hidden size-3.5 shrink-0 text-muted-foreground/70 sm:block" aria-hidden="true" />
	{/if}
	<span class="min-w-0 font-mono text-xs break-all sm:text-[13px]">{name}</span>
</div>
