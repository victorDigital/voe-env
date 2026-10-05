<script lang="ts">
	import { untrack } from 'svelte';
	import { page } from '$app/state';
	import { provideDashboard } from '#lib/dashboard.svelte.ts';
	import AppShell from '#lib/components/AppShell.svelte';
	let { data, children } = $props();
	const dashboard = untrack(() => provideDashboard(data.workspaces, data.selectedWorkspace));
	$effect(() => {
		const id = page.url.searchParams.get('workspace');
		if (id && untrack(() => dashboard.workspaces.some((w) => w.id === id))) dashboard.selected = id;
	});
</script>

<AppShell user={data.user} sidebarOpen={data.sidebarOpen}>
	{@render children()}
</AppShell>
