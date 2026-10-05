<script lang="ts">
	import ActionError from '#lib/components/ActionError.svelte';
	import { page } from '$app/state';
	import { goto } from '$app/navigation';
	import * as Sidebar from '#lib/components/ui/sidebar/index.ts';
	import * as DropdownMenu from '#lib/components/ui/dropdown-menu/index.ts';
	import * as Dialog from '#lib/components/ui/dialog/index.ts';
	import { Button } from '#lib/components/ui/button/index.ts';
	import { Input } from '#lib/components/ui/input/index.ts';
	import { Label } from '#lib/components/ui/label/index.ts';
	import { getHotkeyManager, useHotkeys } from '#lib/hotkeys/manager.svelte.ts';
	import { ariaKeys, formatKeys } from '#lib/hotkeys/utils.ts';
	import RiKeyboardLine from 'remixicon-svelte/icons/keyboard-line';
	import InstallCliDialog from './InstallCliDialog.svelte';
	import { useDashboard } from '#lib/dashboard.svelte.ts';
	import { authClient } from '#lib/auth-client.ts';
	import { isUnlocked, initializeWorkspace } from '#lib/vault-client.ts';
	import RiFolderLockLine from 'remixicon-svelte/icons/folder-lock-line';
	import RiTerminalBoxLine from 'remixicon-svelte/icons/terminal-box-line';
	import RiBookOpenLine from 'remixicon-svelte/icons/book-open-line';
	import RiLogoutBoxLine from 'remixicon-svelte/icons/logout-box-line';
	import RiSettings3Line from 'remixicon-svelte/icons/settings-3-line';
	import RiUser3Line from 'remixicon-svelte/icons/user-3-line';
	import RiExpandUpDownLine from 'remixicon-svelte/icons/expand-up-down-line';
	import RiAddLine from 'remixicon-svelte/icons/add-line';
	import RiCloseLine from 'remixicon-svelte/icons/close-line';
	import RiCheckLine from 'remixicon-svelte/icons/check-line';
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
	const dashboard = useDashboard();
	let installOpen = $state(false);
	let name = $state('');
	let error = $state('');
	let creating = $state(false);
	const navigation = [
		{ label: 'Vault', href: '/dashboard/env', icon: RiFolderLockLine, keys: 'shift+v' },
		{
			label: 'Workspace settings',
			href: '/dashboard/workspace',
			icon: RiSettings3Line,
			keys: 'shift+w'
		}
	];
	const hotkeys = getHotkeyManager()!;
	function destination(href: string) {
		return `${href}${dashboard.selected ? '?workspace=' + encodeURIComponent(dashboard.selected) : ''}`;
	}
	function navigate(href: string) {
		sidebar.setOpenMobile(false);
		goto(destination(href));
	}
	function openInstall() {
		installOpen = true;
		sidebar.setOpenMobile(false);
	}
	useHotkeys('navigation', () => [
		...navigation.map((item) => ({
			id: item.href,
			keys: item.keys,
			description: item.label,
			category: 'Navigation',
			handler: () => navigate(item.href)
		})),
		{
			id: 'account',
			keys: 'shift+a',
			description: 'Account settings',
			category: 'Navigation',
			handler: () => navigate('/dashboard/account')
		},
		{
			id: 'install',
			keys: 'shift+i',
			description: 'Install CLI',
			category: 'Navigation',
			handler: openInstall
		}
	]);
	async function select(id: string) {
		dashboard.selected = id;
		sidebar.setOpenMobile(false);
		const destination =
			page.url.pathname === '/dashboard/workspace' ? page.url.pathname : '/dashboard/env';
		await goto(`${destination}?workspace=${encodeURIComponent(id)}`);
	}
	async function create() {
		creating = true;
		error = '';
		try {
			const result = await authClient.organization.create({
				name: name.trim(),
				slug: `workspace-${crypto.randomUUID()}`
			});
			if (result.error || !result.data)
				throw new Error(result.error?.message || 'Could not create workspace');
			await dashboard.refresh();
			await select(result.data.id);
			await initializeWorkspace(result.data.id);
			await dashboard.refresh();
			dashboard.createOpen = false;
			name = '';
			await goto(`/dashboard/env?workspace=${encodeURIComponent(result.data.id)}`, {
				refreshAll: true
			});
		} catch (e) {
			error = (e as Error).message;
		} finally {
			creating = false;
		}
	}
</script>

<Sidebar.Root collapsible="icon" aria-label="Application sidebar">
	<Sidebar.Header class="gap-3 px-3 pt-0 pb-3 group-data-[collapsible=icon]:px-2">
		<div
			class="flex h-12 shrink-0 items-center justify-between group-data-[collapsible=icon]:justify-center"
		>
			<a
				href="/dashboard/env"
				aria-label="VOE vault"
				class="inline-flex h-9 w-fit shrink-0 items-center justify-center px-2 text-lg font-semibold tracking-tight group-data-[collapsible=icon]:size-8 group-data-[collapsible=icon]:px-0"
				><span class="group-data-[collapsible=icon]:hidden">voe</span><span
					class="hidden group-data-[collapsible=icon]:inline">v</span
				><span class="text-primary">.</span></a
			>
			{#if sidebar.isMobile}<Button
					variant="ghost"
					size="icon-sm"
					aria-label="Close navigation"
					onclick={() => sidebar.setOpenMobile(false)}><RiCloseLine /></Button
				>{/if}
		</div>
		<DropdownMenu.Root>
			<DropdownMenu.Trigger
				disabled={dashboard.working}
				class="flex h-12 w-full min-w-0 items-center gap-2.5 border border-sidebar-border bg-background/40 px-2.5 text-left outline-none group-data-[collapsible=icon]:size-8 group-data-[collapsible=icon]:justify-center group-data-[collapsible=icon]:border-0 group-data-[collapsible=icon]:px-0 hover:bg-sidebar-accent focus-visible:ring-1 focus-visible:ring-ring"
				aria-label="Switch workspace"
			>
				<span
					class="flex size-7 shrink-0 items-center justify-center bg-muted text-xs font-medium group-data-[collapsible=icon]:size-8"
					>{dashboard.workspace?.name.slice(0, 1).toUpperCase() || 'V'}</span
				>
				<span class="min-w-0 flex-1 group-data-[collapsible=icon]:hidden"
					><span class="block truncate text-xs font-medium"
						>{dashboard.workspace?.name || 'Workspace'}</span
					><span class="mt-0.5 block text-[11px] text-muted-foreground"
						>{dashboard.workspace?.role || 'No workspace'}</span
					></span
				><RiExpandUpDownLine
					class="size-3.5 text-muted-foreground group-data-[collapsible=icon]:hidden"
				/>
			</DropdownMenu.Trigger>
			<DropdownMenu.Content side={sidebar.open ? 'bottom' : 'right'} align="start" class="w-60">
				<DropdownMenu.Label>Workspaces</DropdownMenu.Label>
				{#each dashboard.workspaces as workspace}
					<DropdownMenu.Item onSelect={() => select(workspace.id)}
						><span class="min-w-0 flex-1 truncate">{workspace.name}</span
						>{#if workspace.id === dashboard.selected}<RiCheckLine />{/if}</DropdownMenu.Item
					>
				{/each}
				<DropdownMenu.Separator />
				<DropdownMenu.Item
					disabled={!$isUnlocked}
					onSelect={() => {
						sidebar.setOpenMobile(false);
						dashboard.createOpen = true;
						error = '';
					}}><RiAddLine />New workspace</DropdownMenu.Item
				>
			</DropdownMenu.Content>
		</DropdownMenu.Root>
	</Sidebar.Header>
	<Sidebar.Content>
		<Sidebar.Group class="px-3 py-1 group-data-[collapsible=icon]:px-2"
			><Sidebar.Menu>
				{#each navigation as item}<Sidebar.MenuItem
						><Sidebar.MenuButton
							isActive={page.url.pathname === item.href}
							tooltipContent={`${item.label} (${formatKeys(item.keys, hotkeys.mac)})`}
							class="h-9 text-xs text-muted-foreground"
						>
							{#snippet child({ props })}<a
									{...props}
									href={destination(item.href)}
									aria-keyshortcuts={ariaKeys(item.keys, hotkeys.mac)}
									aria-current={page.url.pathname === item.href ? 'page' : undefined}
									onclick={() => sidebar.setOpenMobile(false)}
									><item.icon /><span>{item.label}</span></a
								>{/snippet}
						</Sidebar.MenuButton></Sidebar.MenuItem
					>{/each}
			</Sidebar.Menu></Sidebar.Group
		>
	</Sidebar.Content>
	<Sidebar.Footer class="gap-3 px-3 pb-3 group-data-[collapsible=icon]:px-2">
		<Sidebar.Menu
			><Sidebar.MenuItem
				><Sidebar.MenuButton
					onclick={openInstall}
					aria-keyshortcuts={ariaKeys('shift+i', hotkeys.mac)}
					tooltipContent={`Install CLI (${formatKeys('shift+i', hotkeys.mac)})`}
					class="h-9 text-xs text-muted-foreground"
					><RiTerminalBoxLine /><span>Install CLI</span></Sidebar.MenuButton
				></Sidebar.MenuItem
			><Sidebar.MenuItem
				><Sidebar.MenuButton
					tooltipContent="Documentation"
					class="h-9 text-xs text-muted-foreground"
					>{#snippet child({ props })}<a
							{...props}
							href="https://github.com/victorDigital/voe-env/blob/main/cli/README.md"
							target="_blank"
							rel="noreferrer"><RiBookOpenLine /><span>Documentation</span></a
						>{/snippet}</Sidebar.MenuButton
				></Sidebar.MenuItem
			></Sidebar.Menu
		>
		<div class="border-t border-sidebar-border pt-3">
			<DropdownMenu.Root>
				<DropdownMenu.Trigger
					aria-label="Account menu"
					class="flex w-full min-w-0 items-center gap-2.5 p-1 text-left group-data-[collapsible=icon]:p-0 hover:bg-sidebar-accent"
					><span
						class="flex size-8 shrink-0 items-center justify-center border border-sidebar-border text-xs"
						>{user.name.slice(0, 1).toUpperCase()}</span
					><span class="min-w-0 flex-1 group-data-[collapsible=icon]:hidden"
						><span class="block truncate text-xs font-medium">{user.name}</span><span
							class="mt-0.5 block truncate text-[11px] text-muted-foreground">{user.email}</span
						></span
					><RiExpandUpDownLine
						class="size-3.5 text-muted-foreground group-data-[collapsible=icon]:hidden"
					/></DropdownMenu.Trigger
				>
				<DropdownMenu.Content side="top" align="start" class="w-60"
					><DropdownMenu.Item onSelect={() => navigate('/dashboard/account')}
						><RiUser3Line />Account settings</DropdownMenu.Item
					><DropdownMenu.Item
						onSelect={() => {
							sidebar.setOpenMobile(false);
							hotkeys.helpOpen = true;
						}}
						><RiKeyboardLine />Keyboard shortcuts<DropdownMenu.Shortcut>?</DropdownMenu.Shortcut
						></DropdownMenu.Item
					><DropdownMenu.Separator /><DropdownMenu.Item disabled={signingOut} onSelect={onSignOut}
						><RiLogoutBoxLine />{signingOut ? 'Signing out…' : 'Sign out'}</DropdownMenu.Item
					></DropdownMenu.Content
				>
			</DropdownMenu.Root>
		</div>
	</Sidebar.Footer>
</Sidebar.Root>
<InstallCliDialog bind:open={installOpen} />
<Dialog.Root bind:open={dashboard.createOpen}
	><Dialog.Content class="p-6 sm:max-w-md"
		><Dialog.Header
			><Dialog.Title>New workspace</Dialog.Title><Dialog.Description
				>Everyone you invite can access its folders.</Dialog.Description
			></Dialog.Header
		>
		<form
			onsubmit={(e) => {
				e.preventDefault();
				create();
			}}
			class="space-y-5"
		>
			<div class="space-y-2">
				<Label for="workspace-name">Name</Label><Input
					id="workspace-name"
					aria-label="New workspace name"
					bind:value={name}
					placeholder="Acme"
					required
					maxlength={80}
				/>
			</div>
			<ActionError bind:error /><Dialog.Footer
				><Button
					variant="outline"
					onclick={() => (dashboard.createOpen = false)}
					disabled={creating}>Cancel</Button
				><Button
					type="submit"
					loading={creating}
					hotKey={{
						keys: 'mod+enter',
						description: 'Create workspace',
						category: 'Workspace',
						allowInInput: true
					}}
					disabled={creating || !$isUnlocked || !name.trim()}
					>{creating ? 'Creating…' : 'Create workspace'}</Button
				></Dialog.Footer
			>
		</form></Dialog.Content
	></Dialog.Root
>
