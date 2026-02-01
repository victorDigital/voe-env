<script lang="ts">
	import Folder from '@lucide/svelte/icons/folder';
	import Users from '@lucide/svelte/icons/users';
	import { Button } from '$lib/components/ui/button/index.js';
	import Badge from '$lib/components/ui/badge/badge.svelte';

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

<Button variant="link" size="sm" onclick={onNavigate} class="h-auto gap-1 p-0">
	{#if isShared}
		<Users class="h-4 w-4 text-muted-foreground" />
	{:else}
		<Folder class="h-4 w-4 text-muted-foreground" />
	{/if}
	<span>{name}</span>
	{#if isShared}
		<Badge variant="secondary" class="ml-1 text-xs">
			Shared by {sharedBy?.name || sharedBy?.email}
		</Badge>
		{#if permission === 'read'}
			<Badge variant="outline" class="ml-1 text-xs">Read Only</Badge>
		{/if}
	{/if}
</Button>
