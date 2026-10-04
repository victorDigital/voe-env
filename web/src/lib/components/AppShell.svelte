<script lang="ts">
	import { goto } from '$app/navigation';
	import type { Snippet } from 'svelte';
	import { lock } from '#lib/vault-client.ts';
	import { authClient } from '#lib/auth-client.ts';
	import * as Sidebar from '#lib/components/ui/sidebar/index.ts';
	import AppSidebar from '#lib/components/AppSidebar.svelte';

	let {
		children,
		user,
		sidebarOpen = true
	}: {
		children: Snippet;
		user: { name: string; email: string };
		sidebarOpen?: boolean;
	} = $props();

	let signingOut = $state(false);
	let error = $state('');

	async function signOut() {
		lock();
		signingOut = true;
		error = '';
		try {
			const result = await authClient.signOut();
			if (result.error) throw new Error(result.error.message || 'Could not sign out.');
			await goto('/login', { refreshAll: true });
		} catch (cause) {
			error = cause instanceof Error ? cause.message : 'Could not sign out. Try again.';
		} finally {
			signingOut = false;
		}
	}
</script>

<Sidebar.Provider
	open={sidebarOpen}
	style="--sidebar-width: 15rem; --sidebar-width-icon: 3rem;"
	class="min-w-0"
>
	<AppSidebar {user} {signingOut} onSignOut={signOut} />
	<Sidebar.Inset id="main-content" class="min-w-0">
		<header class="flex h-14 shrink-0 items-center gap-3 border-b border-border px-4 sm:px-6">
			<Sidebar.Trigger aria-label="Toggle navigation" class="size-9 shrink-0" />
			<h1 class="text-sm font-medium">Vault</h1>
		</header>
		{#if error}
			<p
				role="alert"
				class="mx-4 mt-4 border-l-2 border-destructive py-1 pl-3 text-sm text-destructive sm:mx-6"
			>
				{error}
			</p>
		{/if}
		{@render children()}
	</Sidebar.Inset>
</Sidebar.Provider>
