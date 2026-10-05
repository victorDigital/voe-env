<script lang="ts">
	import ActionError from '#lib/components/ActionError.svelte';
	import { onDestroy, onMount, untrack } from 'svelte';
	import { Button } from '#lib/components/ui/button/index.ts';
	import { Input } from '#lib/components/ui/input/index.ts';
	import { Textarea } from '#lib/components/ui/textarea/index.ts';
	import { Label } from '#lib/components/ui/label/index.ts';
	import * as Dialog from '#lib/components/ui/dialog/index.ts';
	import * as DropdownMenu from '#lib/components/ui/dropdown-menu/index.ts';
	import * as Table from '#lib/components/ui/table/index.ts';
	import WorkspaceAccess from '#lib/components/WorkspaceAccess.svelte';
	import ConfirmAction from '#lib/components/ConfirmAction.svelte';
	import FolderTree from '#lib/components/FolderTree.svelte';
	import { useDashboard } from '#lib/dashboard.svelte.ts';
	import {
		api,
		isUnlocked,
		organizationKey,
		decryptWorkspace,
		type Snapshot
	} from '#lib/vault-client.ts';
	import { randomKey, seal, unseal, bytes } from '#lib/vault-crypto.ts';
	import { folderContext, secretContext } from '#lib/vault-format.ts';
	import { permits } from '#lib/permissions.ts';
	import RiAddLine from 'remixicon-svelte/icons/add-line';
	import RiFolderLine from 'remixicon-svelte/icons/folder-line';
	import RiFolderAddLine from 'remixicon-svelte/icons/folder-add-line';
	import RiArrowRightSLine from 'remixicon-svelte/icons/arrow-right-s-line';
	import RiMoreLine from 'remixicon-svelte/icons/more-line';
	import RiSearchLine from 'remixicon-svelte/icons/search-line';
	import RiEyeLine from 'remixicon-svelte/icons/eye-line';
	import RiEyeOffLine from 'remixicon-svelte/icons/eye-off-line';
	import RiFileCopyLine from 'remixicon-svelte/icons/file-copy-line';
	let { data } = $props();
	const dashboard = useDashboard();
	let selected = $derived(dashboard.selected);
	let snapshot = $state<Snapshot | null>(null);
	let folderId = $state('');
	let values = $state<Record<string, string>>({});
	let revealed = $state(false);
	let busy = $derived(dashboard.working);
	let error = $state('');
	let notice = $state('');
	let query = $state('');
	let folderName = $state('');
	let secretName = $state('');
	let secretValue = $state('');
	let folderOpen = $state(false);
	let treeOpen = $state(false);
	let folderPath = $state<HTMLElement | null>(null);
	let folderPathWidth = $state(0);
	let secretOpen = $state(false);
	let editing = $state(false);
	let deleting = $state<{ id: string; name: string; folder: boolean } | null>(null);
	let confirmOpen = $state(false);
	let requestId = 0;
	let currentFolder = $derived(snapshot?.folders.find((f) => f.id === folderId));
	let canWrite = $derived(
		!!snapshot && permits(snapshot.role, 'write') && !snapshot.rotationRequired
	);
	let hasSecrets = $derived(!!snapshot?.secrets.some((secret) => secret.folderId === folderId));
	let secrets = $derived(
		(
			snapshot?.secrets.filter(
				(s) => s.folderId === folderId && s.name.toLowerCase().includes(query.toLowerCase())
			) || []
		).sort((a, b) => a.name.localeCompare(b.name))
	);
	let crumbs = $derived.by(() => {
		const result: { id: string; name: string }[] = [];
		let current = currentFolder;
		while (current && result.length < 64) {
			result.unshift({ id: current.id, name: current.parentId ? current.name : 'Vault' });
			current = snapshot?.folders.find((f) => f.id === current?.parentId);
		}
		return result;
	});
	$effect(() => {
		selected;
		dashboard.revision;
		untrack(loadWorkspace);
	});
	$effect(() => {
		if (!$isUnlocked) {
			values = {};
			secretValue = '';
			secretOpen = false;
			folderOpen = false;
			revealed = false;
		}
	});
	onMount(() => {
		dashboard.header = folderHeader;
		return () => {
			dashboard.header = null;
		};
	});
	$effect(() => {
		folderId;
		folderPathWidth;
		folderPath?.scrollTo({ left: folderPath.scrollWidth });
	});
	onDestroy(() => {
		requestId++;
		values = {};
		secretValue = '';
	});
	async function loadWorkspace() {
		const id = selected,
			request = ++requestId;
		values = {};
		error = '';
		if (snapshot?.organizationId !== id) {
			snapshot = null;
			folderId = '';
			treeOpen = false;
			query = '';
			revealed = false;
		}
		if (!id) {
			snapshot = null;
			return;
		}
		try {
			const next = await api<Snapshot>(`/api/workspaces/${id}`);
			if (request !== requestId) return;
			snapshot = next;
			if (!next.folders.some((f) => f.id === folderId))
				folderId = next.folders.find((f) => !f.parentId)?.id || '';
			if ($isUnlocked && next.envelopes.length) {
				const decrypted = await decryptWorkspace(next);
				if (request === requestId && $isUnlocked) values = decrypted;
			}
		} catch (e) {
			if (request === requestId) error = (e as Error).message;
		}
	}
	async function run(action: () => Promise<unknown>) {
		if (busy) return;
		dashboard.working = true;
		error = '';
		notice = '';
		try {
			await action();
		} catch (e) {
			error = (e as Error).message;
		} finally {
			dashboard.working = false;
		}
	}
	function openSecret(name = '', value = '') {
		editing = !!name;
		secretName = name;
		secretValue = value;
		secretOpen = true;
		error = '';
	}
	function navigate(id: string) {
		folderId = id;
		query = '';
		notice = '';
	}
	async function copy(value: string) {
		try {
			await navigator.clipboard.writeText(value);
			notice = 'Copied';
		} catch {
			error = 'Could not copy to clipboard.';
		}
	}
	async function save() {
		if (!snapshot) return;
		try {
			await api(`/api/workspaces/${snapshot.organizationId}`, { ...snapshot, action: 'save' });
		} catch (e) {
			await loadWorkspace();
			throw e;
		}
		await loadWorkspace();
	}
	async function createFolder() {
		if (!snapshot || !folderName.trim() || !folderId) return;
		const key = await organizationKey(snapshot);
		const folderKey = randomKey();
		const id = crypto.randomUUID();
		const folder = {
			id,
			parentId: folderId,
			name: folderName.trim(),
			wrappedKey: await seal(key, folderKey, folderContext(selected, id, snapshot.epoch))
		};
		key.fill(0);
		folderKey.fill(0);
		snapshot = { ...snapshot, folders: [...snapshot.folders, folder] };
		await save();
		folderName = '';
		folderOpen = false;
	}
	async function saveSecret() {
		if (!snapshot || !currentFolder) return;
		if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(secretName))
			throw new Error('Use a valid environment variable name');
		const orgKey = await organizationKey(snapshot);
		const key = await unseal(
			orgKey,
			currentFolder.wrappedKey,
			folderContext(selected, folderId, snapshot.epoch)
		);
		orgKey.fill(0);
		const old = snapshot.secrets.find((s) => s.folderId === folderId && s.name === secretName);
		const id = old?.id || crypto.randomUUID();
		const secret = {
			id,
			folderId,
			name: secretName,
			encryptedValue: await seal(
				key,
				bytes(secretValue),
				secretContext(selected, folderId, id, secretName, snapshot.epoch)
			)
		};
		key.fill(0);
		snapshot = { ...snapshot, secrets: [...snapshot.secrets.filter((s) => s.id !== id), secret] };
		await save();
		secretName = '';
		secretValue = '';
		secretOpen = false;
	}
	async function deleteSecret(id: string) {
		if (!snapshot) return;
		snapshot = { ...snapshot, secrets: snapshot.secrets.filter((s) => s.id !== id) };
		await save();
	}
	async function deleteFolder() {
		if (!snapshot || !currentFolder?.parentId) return;
		if (
			snapshot.folders.some((f) => f.parentId === folderId) ||
			snapshot.secrets.some((s) => s.folderId === folderId)
		)
			throw new Error('Empty this folder before deleting it');
		const parent = currentFolder.parentId;
		snapshot = { ...snapshot, folders: snapshot.folders.filter((f) => f.id !== folderId) };
		folderId = parent;
		await save();
	}
</script>

{#snippet folderHeader()}
	{#if currentFolder && snapshot?.envelopes.length}
		<div class="flex min-w-0 flex-1 items-center gap-2">
			<Button
				variant="ghost"
				size="icon"
				class="shrink-0 md:hidden"
				aria-label="Folders"
				title="Folders"
				aria-expanded={treeOpen}
				aria-controls="folder-navigation"
				onclick={() => (treeOpen = !treeOpen)}
			>
				<RiFolderLine />
			</Button>
			<nav
				aria-label="Folder path"
				bind:this={folderPath}
				bind:clientWidth={folderPathWidth}
				class="flex min-w-0 flex-1 [scrollbar-width:none] items-center gap-1 overflow-x-auto text-xs [&::-webkit-scrollbar]:hidden"
			>
				{#each crumbs as crumb, index}
					{#if index}<RiArrowRightSLine class="size-4 shrink-0 text-muted-foreground" />{/if}
					<button
						class="max-w-32 shrink-0 truncate px-1 py-1 font-medium hover:text-foreground disabled:text-foreground sm:max-w-64"
						class:text-muted-foreground={index < crumbs.length - 1}
						onclick={() => navigate(crumb.id)}
						disabled={index === crumbs.length - 1}>{crumb.name}</button
					>
				{/each}
			</nav>
			{#if currentFolder?.parentId && canWrite}<DropdownMenu.Root
					><DropdownMenu.Trigger
						class="inline-flex size-8 items-center justify-center hover:bg-muted"
						aria-label="Folder actions"><RiMoreLine class="size-4" /></DropdownMenu.Trigger
					><DropdownMenu.Content align="end"
						><DropdownMenu.Item
							variant="destructive"
							disabled={busy ||
								!!snapshot?.secrets.some((s) => s.folderId === folderId) ||
								!!snapshot?.folders.some((f) => f.parentId === folderId)}
							onSelect={() => {
								deleting = { id: folderId, name: currentFolder!.name, folder: true };
								confirmOpen = true;
							}}>Delete empty folder</DropdownMenu.Item
						></DropdownMenu.Content
					></DropdownMenu.Root
				>{/if}
		</div>
	{:else}<span class="text-xs text-muted-foreground">Vault</span>{/if}
{/snippet}

<svelte:head><title>Vault · VOE</title></svelte:head>
<div class="flex w-full flex-1 flex-col px-4 pt-4 pb-7 sm:px-8 md:py-0 md:pl-0 lg:pr-10">
	{#if error && !secretOpen && !folderOpen}<p role="alert" class="mb-5 text-xs text-destructive">
			{error}
		</p>{/if}
	<WorkspaceAccess userId={data.user.id} {snapshot} refresh={loadWorkspace}>
		<div
			class="grid min-w-0 gap-x-5 gap-y-3 md:flex-1 md:grid-cols-[12rem_minmax(0,1fr)] md:grid-rows-[1fr] md:gap-x-7 lg:grid-cols-[14rem_minmax(0,1fr)]"
		>
			<aside
				class="min-w-0 md:col-start-1 md:row-start-1 md:block md:border-r"
				class:hidden={!treeOpen}
			>
				<div
					id="folder-navigation"
					class="max-h-72 overflow-auto md:sticky md:top-6 md:max-h-[calc(100dvh-7rem)] md:pt-4"
				>
					{#key snapshot?.organizationId}
						<FolderTree
							folders={snapshot?.folders || []}
							selected={folderId}
							onnavigate={(id: string) => {
								navigate(id);
								treeOpen = false;
							}}
						/>
					{/key}
				</div>
			</aside>
			<div class="min-w-0 md:col-start-2 md:pt-4 md:pb-7">
				<div class="mb-3 flex min-h-9 items-center gap-2">
					{#if hasSecrets}
						<div class="relative min-w-0 flex-1 sm:max-w-xs">
							<RiSearchLine
								class="pointer-events-none absolute top-2.5 left-2.5 size-3.5 text-muted-foreground"
							/>
							<Input
								class="h-9 border-transparent bg-muted/30 pl-8 focus-visible:border-input"
								aria-label="Search this folder"
								placeholder="Filter…"
								bind:value={query}
							/>
						</div>
					{/if}
					<div class="ml-auto flex shrink-0 items-center gap-1">
						{#if hasSecrets}
							<Button
								variant="ghost"
								size="icon"
								aria-label={revealed ? 'Hide values' : 'Show values'}
								title={revealed ? 'Hide values' : 'Show values'}
								onclick={() => (revealed = !revealed)}
								>{#if revealed}<RiEyeOffLine />{:else}<RiEyeLine />{/if}</Button
							>
						{/if}
						{#if canWrite}
							<Button
								variant="ghost"
								class="size-8 px-0 lg:w-auto lg:px-2.5"
								aria-label="New folder"
								title="New folder"
								disabled={busy}
								onclick={() => {
									folderOpen = true;
									error = '';
								}}><RiFolderAddLine /><span class="hidden lg:inline">New folder</span></Button
							>
							<Button disabled={busy} onclick={() => openSecret()}><RiAddLine />Add secret</Button>
						{/if}
					</div>
				</div>
				{#if secrets.length}
					<div class="border-y">
						<Table.Root class="w-full table-fixed text-xs" aria-label="Secrets">
							<colgroup><col class="w-[48%] sm:w-[46%]" /><col /><col class="w-20" /></colgroup>
							<Table.Header
								><Table.Row class="border-0 hover:bg-transparent">
									<Table.Head class="h-0 p-0"><span class="sr-only">Name</span></Table.Head>
									<Table.Head class="h-0 p-0"><span class="sr-only">Value</span></Table.Head>
									<Table.Head class="h-0 p-0"><span class="sr-only">Actions</span></Table.Head>
								</Table.Row></Table.Header
							>
							<Table.Body>
								{#each secrets as secret}<Table.Row class="group"
										><Table.Cell class="max-w-0 py-3.5 pl-3"
											><span class="block truncate font-mono text-xs" title={secret.name}
												>{secret.name}</span
											></Table.Cell
										><Table.Cell class="max-w-0"
											><code
												class="block truncate text-xs text-muted-foreground"
												class:tracking-widest={!revealed}
												>{revealed ? (values[secret.id] ?? 'Locked') : '••••••••••••'}</code
											></Table.Cell
										><Table.Cell class="px-1"
											><div class="flex justify-end">
												<Button
													variant="ghost"
													size="icon-sm"
													aria-label={`Copy ${secret.name}`}
													disabled={values[secret.id] === undefined}
													onclick={() => copy(values[secret.id])}
													><RiFileCopyLine class="size-3.5" /></Button
												>{#if canWrite}<DropdownMenu.Root
														><DropdownMenu.Trigger
															disabled={busy}
															class="inline-flex size-7 items-center justify-center hover:bg-muted"
															aria-label={`Actions for ${secret.name}`}
															><RiMoreLine class="size-4" /></DropdownMenu.Trigger
														><DropdownMenu.Content align="end"
															><DropdownMenu.Item
																disabled={values[secret.id] === undefined}
																onSelect={() => openSecret(secret.name, values[secret.id])}
																>Edit secret</DropdownMenu.Item
															><DropdownMenu.Separator /><DropdownMenu.Item
																variant="destructive"
																onSelect={() => {
																	deleting = { id: secret.id, name: secret.name, folder: false };
																	confirmOpen = true;
																}}>Delete secret</DropdownMenu.Item
															></DropdownMenu.Content
														></DropdownMenu.Root
													>{/if}
											</div></Table.Cell
										></Table.Row
									>{/each}
							</Table.Body>
						</Table.Root>
					</div>
				{:else}
					<div
						role="status"
						class="flex min-h-32 items-center justify-center gap-2 text-xs text-muted-foreground"
					>
						{#if query}No matches<Button variant="link" size="sm" onclick={() => (query = '')}
								>Clear filter</Button
							>{:else}No secrets{/if}
					</div>
				{/if}
				<p role="status" class="text-xs text-muted-foreground" class:mt-2={!!notice}>{notice}</p>
			</div>
		</div>
	</WorkspaceAccess>
</div>
<Dialog.Root
	bind:open={secretOpen}
	onOpenChange={(open) => {
		if (!open) secretValue = '';
	}}
	><Dialog.Content class="p-6 sm:max-w-lg"
		><Dialog.Header
			><Dialog.Title>{editing ? 'Edit secret' : 'Add secret'}</Dialog.Title><Dialog.Description
				class="sr-only">Save an encrypted environment variable in this folder.</Dialog.Description
			></Dialog.Header
		>
		<form
			class="space-y-5"
			onsubmit={(e) => {
				e.preventDefault();
				run(saveSecret);
			}}
		>
			<div class="space-y-2">
				<Label for="secret-name">Name</Label><Input
					id="secret-name"
					class="font-mono"
					bind:value={secretName}
					readonly={editing}
					required
					pattern="[A-Za-z_][A-Za-z0-9_]*"
					placeholder="DATABASE_URL"
				/>
			</div>
			<div class="space-y-2">
				<Label for="secret-value">Value</Label><Textarea
					id="secret-value"
					class="max-h-64 min-h-28 font-mono text-xs"
					bind:value={secretValue}
					autocomplete="off"
					spellcheck={false}
					placeholder="Enter a value"
				/>
			</div>
			<ActionError bind:error /><Dialog.Footer
				><Button variant="outline" disabled={busy} onclick={() => (secretOpen = false)}
					>Cancel</Button
				><Button type="submit" disabled={busy}>{busy ? 'Saving…' : 'Save secret'}</Button
				></Dialog.Footer
			>
		</form></Dialog.Content
	></Dialog.Root
>
<Dialog.Root bind:open={folderOpen}
	><Dialog.Content class="p-6 sm:max-w-md"
		><Dialog.Header
			><Dialog.Title>New folder</Dialog.Title><Dialog.Description class="sr-only"
				>Create a subfolder in the current folder.</Dialog.Description
			></Dialog.Header
		>
		<form
			class="space-y-5"
			onsubmit={(e) => {
				e.preventDefault();
				run(createFolder);
			}}
		>
			<div class="space-y-2">
				<Label for="folder-name">Folder name</Label><Input
					id="folder-name"
					bind:value={folderName}
					placeholder="production"
					required
					pattern="[^:]+"
				/>
			</div>
			<ActionError bind:error /><Dialog.Footer
				><Button variant="outline" disabled={busy} onclick={() => (folderOpen = false)}
					>Cancel</Button
				><Button type="submit" disabled={busy}>Create folder</Button></Dialog.Footer
			>
		</form></Dialog.Content
	></Dialog.Root
>
<ConfirmAction
	bind:error
	bind:open={confirmOpen}
	title={`Delete ${deleting?.name || 'item'}?`}
	description="This cannot be undone."
	label="Delete"
	{busy}
	onconfirm={() =>
		run(async () => {
			if (!deleting) return;
			if (deleting.folder) await deleteFolder();
			else await deleteSecret(deleting.id);
			confirmOpen = false;
		})}
/>
