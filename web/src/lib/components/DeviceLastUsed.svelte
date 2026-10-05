<script lang="ts">
	let { value }: { value: string | null } = $props();
	let date = $derived(value ? new Date(value) : null);
</script>

<span class="mt-1 block text-[11px] text-muted-foreground">
	Last used {#if date}<time datetime={value!} title={date.toLocaleString()}
			>{date.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })}</time
		>{:else}—{/if}
</span>
