<script lang="ts">
	import { page } from '$app/state';
	import * as Sidebar from '#lib/components/ui/sidebar/index.ts';
	import RiFolderLockLine from 'remixicon-svelte/icons/folder-lock-line';
	import RiTerminalBoxLine from 'remixicon-svelte/icons/terminal-box-line';
	import RiBookOpenLine from 'remixicon-svelte/icons/book-open-line';
	import RiLogoutBoxLine from 'remixicon-svelte/icons/logout-box-line';
	import RiCloseLine from 'remixicon-svelte/icons/close-line';
	import { Button } from '#lib/components/ui/button/index.ts';

	let {
		user,
		signingOut,
		onSignOut
	}: {
		user: { name: string; email: string };
		signingOut: boolean;
		onSignOut: () => Promise<void>;
	} = $props();

	const sidebar = Sidebar.useSidebar();
	const navigation = [
		{ label: 'Vault', href: '/dashboard/env', icon: RiFolderLockLine },
		{ label: 'Install CLI', href: '/#install', icon: RiTerminalBoxLine },
		{
			label: 'CLI documentation',
			href: 'https://github.com/victorDigital/voe-env/blob/main/cli/README.md',
			icon: RiBookOpenLine
		}
	];
</script>

<Sidebar.Root collapsible="icon" variant="sidebar" aria-label="Application sidebar">
	<Sidebar.Header
		class="h-14 justify-center border-b border-sidebar-border px-3 group-data-[collapsible=icon]:px-2"
	>
		<div class="flex min-w-0 items-center justify-between gap-2">
			<a
				href="/"
				aria-label="VOE homepage"
				class="px-1 text-xl font-semibold tracking-tight group-data-[collapsible=icon]:px-0"
				><span class="group-data-[collapsible=icon]:hidden">voe</span><span
					class="hidden group-data-[collapsible=icon]:inline">v</span
				><span class="text-primary">.</span></a
			>
			{#if sidebar.isMobile}
				<Button
					variant="ghost"
					size="icon"
					aria-label="Close navigation"
					onclick={() => sidebar.setOpenMobile(false)}><RiCloseLine /></Button
				>
			{/if}
		</div>
	</Sidebar.Header>
	<Sidebar.Content>
		<nav aria-label="Main navigation">
			<Sidebar.Group class="p-2">
				<Sidebar.Menu>
					{#each navigation as item}
						<Sidebar.MenuItem>
							<Sidebar.MenuButton
								isActive={page.url.pathname === item.href}
								tooltipContent={item.label}
								class="h-9 border-l-2 border-transparent text-sm data-active:border-sidebar-primary"
							>
								{#snippet child({ props })}
									<a
										{...props}
										href={item.href}
										aria-current={page.url.pathname === item.href ? 'page' : undefined}
										onclick={() => sidebar.setOpenMobile(false)}
									>
										<item.icon aria-hidden="true" />
										<span>{item.label}</span>
									</a>
								{/snippet}
							</Sidebar.MenuButton>
						</Sidebar.MenuItem>
					{/each}
				</Sidebar.Menu>
			</Sidebar.Group>
		</nav>
	</Sidebar.Content>
	<Sidebar.Footer
		class="gap-3 border-t border-sidebar-border p-3 group-data-[collapsible=icon]:p-2"
	>
		<div class="min-w-0 px-1 group-data-[collapsible=icon]:hidden">
			<p class="truncate text-sm font-medium" title={user.name}>{user.name}</p>
			<p class="mt-0.5 text-xs break-all text-muted-foreground" title={user.email}>{user.email}</p>
		</div>
		<Sidebar.Menu>
			<Sidebar.MenuItem>
				<Sidebar.MenuButton
					onclick={onSignOut}
					disabled={signingOut}
					tooltipContent="Sign out"
					class="h-9 text-sm"
				>
					<RiLogoutBoxLine aria-hidden="true" />
					<span>{signingOut ? 'Signing out…' : 'Sign out'}</span>
				</Sidebar.MenuButton>
			</Sidebar.MenuItem>
		</Sidebar.Menu>
	</Sidebar.Footer>
</Sidebar.Root>
