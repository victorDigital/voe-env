<script lang="ts">
	import Folder from 'remixicon-svelte/icons/folder-line';
	import Users from 'remixicon-svelte/icons/group-line';

	let {
		name,
		onNavigate,
		isShared,
		sharedBy,
		permission
	}: {
		name: string;
		onNavigate: () => void;
		isShared?: boolean;
		sharedBy?: { email: string; name: string };
		permission?: 'read' | 'readwrite';
	} = $props();
</script>

<button
	type="button"
	onclick={onNavigate}
	aria-label="Open folder {name}"
	class="flex max-w-full items-start gap-2.5 text-left transition-colors hover:text-muted-foreground"
>
	{#if isShared}
		<Users class="mt-0.5 size-4 shrink-0 text-muted-foreground" />
	{:else}
		<Folder class="mt-0.5 size-4 shrink-0 text-muted-foreground" />
	{/if}
	<span class="min-w-0">
		<span class="block text-xs font-medium break-all sm:text-sm">{name}</span>
		{#if isShared}
			<span
				class="mt-1 block truncate text-[11px] text-muted-foreground"
				title="Shared by {sharedBy?.name || sharedBy?.email}"
				>{permission === 'read' ? 'View only' : 'Shared folder'}</span
			>
		{/if}
	</span>
</button>
