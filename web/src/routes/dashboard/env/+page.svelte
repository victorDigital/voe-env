<script lang="ts">
	import ActionError from '#lib/components/ActionError.svelte';
	import { onDestroy, untrack } from 'svelte';
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
	let secretOpen = $state(false);
	let editing = $state(false);
	let deleting = $state<{ id: string; name: string; folder: boolean } | null>(null);
	let confirmOpen = $state(false);
	let requestId = 0;
	let currentFolder = $derived(snapshot?.folders.find((f) => f.id === folderId));
	let canWrite = $derived(
		!!snapshot && permits(snapshot.role, 'write') && !snapshot.rotationRequired
	);
	let folders = $derived(
		(
			snapshot?.folders.filter(
				(f) => f.parentId === folderId && f.name.toLowerCase().includes(query.toLowerCase())
			) || []
		).sort((a, b) => a.name.localeCompare(b.name))
	);
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

<svelte:head><title>Vault · VOE</title></svelte:head>
<div class="mx-auto w-full max-w-[1440px] px-4 py-7 sm:px-8 lg:px-10">
	{#if error && !secretOpen && !folderOpen}<p role="alert" class="mb-5 text-xs text-destructive">
			{error}
		</p>{/if}
	<WorkspaceAccess userId={data.user.id} {snapshot} refresh={loadWorkspace}>
		<div
			class="grid min-w-0 gap-5 md:grid-cols-[12rem_minmax(0,1fr)] md:gap-7 lg:grid-cols-[14rem_minmax(0,1fr)]"
		>
			<aside class="min-w-0 border-b pb-3 md:border-r md:border-b-0 md:pr-4 md:pb-0">
				<div class="md:sticky md:top-6">
					<p class="mb-3 hidden px-3 text-[11px] font-medium text-muted-foreground md:block">
						Folders
					</p>
					<button
						type="button"
						class="flex min-h-11 w-full items-center gap-2 text-left text-xs font-medium outline-none focus-visible:ring-1 focus-visible:ring-ring md:hidden"
						aria-expanded={treeOpen}
						aria-controls="folder-navigation"
						onclick={() => (treeOpen = !treeOpen)}
					>
						<RiFolderLine class="size-4 text-muted-foreground" />Folders
						<RiArrowRightSLine
							class={`ml-auto size-4 text-muted-foreground ${treeOpen ? 'rotate-90' : ''}`}
						/>
					</button>
					<div
						id="folder-navigation"
						class="max-h-72 overflow-auto md:block md:max-h-[calc(100dvh-10rem)]"
						class:hidden={!treeOpen}
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
				</div>
			</aside>
			<div class="min-w-0">
				<div class="mb-7 flex min-w-0 flex-wrap items-center justify-between gap-4">
					<nav aria-label="Folder path" class="flex min-w-0 flex-wrap items-center gap-1 text-sm">
						{#each crumbs as crumb, index}{#if index}<RiArrowRightSLine
									class="size-4 shrink-0 text-muted-foreground"
								/>{/if}<button
								class="max-w-64 truncate px-1 py-1 font-medium hover:text-foreground disabled:text-foreground"
								class:text-muted-foreground={index < crumbs.length - 1}
								onclick={() => navigate(crumb.id)}
								disabled={index === crumbs.length - 1}>{crumb.name}</button
							>{/each}
					</nav>
					{#if canWrite}<div class="flex items-center gap-2">
							<Button
								variant="outline"
								disabled={busy}
								onclick={() => {
									folderOpen = true;
									error = '';
								}}><RiFolderLine />New folder</Button
							><Button disabled={busy} onclick={() => openSecret()}><RiAddLine />Add secret</Button>
						</div>{/if}
				</div>
				<div class="mb-3 flex items-center gap-3">
					<div class="relative w-full max-w-xs">
						<RiSearchLine
							class="pointer-events-none absolute top-2.5 left-2.5 size-3.5 text-muted-foreground"
						/><Input
							class="h-9 border-transparent bg-muted/30 pl-8 focus-visible:border-input"
							aria-label="Search this folder"
							placeholder="Filter by name…"
							bind:value={query}
						/>
					</div>
					<span role="status" class="ml-auto text-xs text-muted-foreground">{notice}</span>
					<Button
						variant="ghost"
						size="icon"
						aria-label={revealed ? 'Hide values' : 'Show values'}
						onclick={() => (revealed = !revealed)}
						>{#if revealed}<RiEyeOffLine />{:else}<RiEyeLine />{/if}</Button
					>
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
				<div class="border-y">
					<Table.Root class="w-full table-fixed text-xs">
						<Table.Header
							><Table.Row class="hover:bg-transparent"
								><Table.Head class="w-[48%] pl-3 text-[11px] font-normal sm:w-[46%]"
									>Name</Table.Head
								><Table.Head class="text-[11px] font-normal">Value</Table.Head><Table.Head
									class="w-20"><span class="sr-only">Actions</span></Table.Head
								></Table.Row
							></Table.Header
						>
						<Table.Body>
							{#each folders as folder}<Table.Row class="group"
									><Table.Cell colspan={3} class="p-0"
										><button
											onclick={() => navigate(folder.id)}
											class="flex min-h-12 w-full min-w-0 items-center gap-3 px-3 text-left"
											><RiFolderLine class="size-4 shrink-0 text-muted-foreground" /><span
												class="truncate">{folder.name}</span
											><RiArrowRightSLine class="ml-auto size-4 text-muted-foreground" /></button
										></Table.Cell
									></Table.Row
								>{/each}
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
							{#if !folders.length && !secrets.length}<Table.Row class="hover:bg-transparent"
									><Table.Cell colspan={3} class="h-44 text-center text-muted-foreground"
										>{query ? 'No matches.' : 'This folder is empty.'}</Table.Cell
									></Table.Row
								>{/if}
						</Table.Body>
					</Table.Root>
				</div>
				<p class="mt-3 text-[11px] text-muted-foreground">
					{folders.length}
					{folders.length === 1 ? 'folder' : 'folders'}<span class="mx-2">·</span>{secrets.length}
					{secrets.length === 1 ? 'secret' : 'secrets'}
				</p>
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
