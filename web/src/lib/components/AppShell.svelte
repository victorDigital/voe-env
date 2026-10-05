<script lang="ts">
	import { page } from '$app/state';
	import { isUnlocked } from '#lib/vault-client.ts';
	import { Button } from '#lib/components/ui/button/index.ts';
	import RiLockLine from 'remixicon-svelte/icons/lock-line';
	import { goto } from '$app/navigation';
	import type { Snippet } from 'svelte';
	import { lock } from '#lib/vault-client.ts';
	import { authClient } from '#lib/auth-client.ts';
	import * as Sidebar from '#lib/components/ui/sidebar/index.ts';
	import AppSidebar from '#lib/components/AppSidebar.svelte';
	import { useDashboard } from '#lib/dashboard.svelte.ts';

	let {
		children,
		user,
		sidebarOpen = true
	}: {
		children: Snippet;
		user: { name: string; email: string };
		sidebarOpen?: boolean;
	} = $props();

	const dashboard = useDashboard();
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
	style="--sidebar-width: 14rem; --sidebar-width-icon: 3rem;"
	class="min-w-0"
>
	<AppSidebar {user} {signingOut} onSignOut={signOut} />
	<Sidebar.Inset id="main-content" class="min-w-0">
		<header class="flex h-12 shrink-0 items-center gap-3 border-b border-border px-1.5">
			<Sidebar.Trigger aria-label="Toggle navigation" class="size-9 shrink-0" />
			{#if dashboard.header && $isUnlocked}
				{@render dashboard.header()}
			{:else}
				<span class="text-xs text-muted-foreground"
					>{page.url.pathname === '/dashboard/account'
						? 'Account settings'
						: page.url.pathname === '/dashboard/workspace'
							? 'Workspace settings'
							: 'Vault'}</span
				>
			{/if}
			{#if $isUnlocked}<Button
					class={dashboard.header
						? 'ml-auto size-8 px-0 text-muted-foreground sm:h-7 sm:w-auto sm:px-2.5'
						: 'ml-auto text-muted-foreground'}
					variant="ghost"
					size="sm"
					aria-label="Lock vault"
					title="Lock vault"
					onclick={lock}
					><RiLockLine class="size-3.5" /><span class={dashboard.header ? 'hidden sm:inline' : ''}
						>Lock vault</span
					></Button
				>{/if}
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
