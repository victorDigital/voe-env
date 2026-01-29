<script lang="ts">
	import Lock from '@lucide/svelte/icons/lock';
	import LockOpen from '@lucide/svelte/icons/lock-open';
	import Spinner from '$lib/components/ui/spinner/spinner.svelte';

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

<div class="flex items-center gap-1">
	{#if isUnlocking}
		<Spinner class="h-4 w-4 text-muted-foreground" />
	{:else if isDecrypted}
		<LockOpen class="h-4 w-4 text-muted-foreground" />
	{:else}
		<Lock class="h-4 w-4 text-muted-foreground" />
	{/if}
	<span>{name}</span>
</div>
