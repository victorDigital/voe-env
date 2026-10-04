<script lang="ts">
	import { onMount } from 'svelte';
	import { Button } from '#lib/components/ui/button/index.ts';
	import { Input } from '#lib/components/ui/input/index.ts';
	import VaultAccess from '#lib/components/VaultAccess.svelte';
	import { authClient } from '#lib/auth-client.ts';
	import {
		api,
		isUnlocked,
		identity,
		lock,
		initializeWorkspace,
		organizationKey,
		decryptWorkspace,
		rotateWorkspace,
		addBackupPasskey,
		type Snapshot
	} from '#lib/vault-client.ts';
	import { randomKey, seal, unseal, bytes, wrapTo, fingerprint } from '#lib/vault-crypto.ts';
	import {
		context,
		folderContext,
		secretContext,
		orgContext,
		folderPath
	} from '#lib/vault-format.ts';
	import { permits } from '#lib/permissions.ts';
	let { data } = $props();
	let workspaces = $state<{ id: string; name: string; role: string }[]>([]);
	let selected = $state('');
	let snapshot = $state<Snapshot | null>(null);
	let folderId = $state('');
	let values = $state<Record<string, string>>({});
	let revealed = $state(false);
	let busy = $state(false);
	let error = $state('');
	let notice = $state('');
	let passkeys = $state<{ id: string; name?: string | null }[]>([]);
	let ownDevices = $state<{ id: string; revoked: boolean }[]>([]);
	let deleteName = $state('');
	let workspaceName = $state('');
	let folderName = $state('');
	let secretName = $state('');
	let secretValue = $state('');
	let email = $state('');
	let role = $state<'admin' | 'member' | 'viewer'>('member');
	let settings = $state(false);
	let verifiedFingerprint = $state('');
	let recipientId = $state('');
	let ownFingerprint = $state('');
	let currentFolder = $derived(snapshot?.folders.find((f) => f.id === folderId));
	let canWrite = $derived(
		!!snapshot && permits(snapshot.role, 'write') && !snapshot.rotationRequired
	);
	let canManage = $derived(!!snapshot && permits(snapshot.role, 'provision'));
	onMount(() => {
		run(loadWorkspaces);
	});
	$effect(() => {
		if (!$isUnlocked) {
			values = {};
			secretValue = '';
			ownFingerprint = '';
		}
	});
	async function run(action: () => Promise<unknown>) {
		if (busy) return;
		busy = true;
		error = '';
		notice = '';
		try {
			await action();
		} catch (e) {
			error = (e as Error).message;
		} finally {
			busy = false;
		}
	}
	async function loadAccountSettings() {
		const keys = await authClient.passkey.listUserPasskeys();
		if (keys.error) throw new Error(keys.error.message);
		passkeys = keys.data || [];
		ownDevices = await api('/api/devices');
	}
	async function loadWorkspaces() {
		workspaces = await api('/api/workspaces');
		if (!workspaces.some((w) => w.id === selected)) selected = workspaces[0]?.id || '';
		if (selected) await loadWorkspace();
		else {
			snapshot = null;
			values = {};
		}
	}
	async function loadWorkspace() {
		values = {};
		snapshot = await api<Snapshot>(`/api/workspaces/${selected}`);
		if (!snapshot.folders.some((f) => f.id === folderId))
			folderId = snapshot.folders.find((f) => !f.parentId)?.id || '';
		if ($isUnlocked && snapshot.envelopes.length) values = await decryptWorkspace(snapshot);
		if ($isUnlocked) ownFingerprint = await fingerprint(identity().publicKey);
	}
	async function createWorkspace() {
		if (!workspaceName.trim()) return;
		const result = await authClient.organization.create({
			name: workspaceName.trim(),
			slug: `workspace-${crypto.randomUUID()}`
		});
		if (result.error || !result.data)
			throw new Error(result.error?.message || 'Could not create workspace');
		selected = result.data.id;
		await initializeWorkspace(selected);
		workspaceName = '';
		await loadWorkspaces();
	}
	async function save() {
		if (!snapshot) return;
		try {
			await api(`/api/workspaces/${selected}`, { ...snapshot, action: 'save' });
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
	}
	async function deleteSecret(id: string) {
		if (!snapshot || !confirm('Delete this secret?')) return;
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
	async function invite() {
		const result = await authClient.organization.inviteMember({
			organizationId: selected,
			email: email.trim(),
			role
		});
		if (result.error) throw new Error(result.error.message);
		email = '';
		notice = 'Invitation sent. Approve their encryption access after they join.';
	}
	async function provision() {
		if (!snapshot) return;
		const member = snapshot.members.find((m) => m.userId === recipientId);
		if (!member?.publicKey) throw new Error('This member must finish vault setup first');
		const expected = await fingerprint(member.publicKey);
		if (verifiedFingerprint.trim().toLowerCase().replace(/\s/g, '') !== expected)
			throw new Error(
				'Ask this member for their full fingerprint through a trusted channel and paste it here'
			);
		const key = await organizationKey(snapshot);
		const recipient = `user:${member.userId}`;
		const wrappedKey = await wrapTo(
			member.publicKey,
			key,
			orgContext(selected, recipient, snapshot.epoch)
		);
		const identityBinding = await seal(
			key,
			bytes(member.publicKey),
			context('recipient', selected, recipient, snapshot.epoch)
		);
		key.fill(0);
		await api(`/api/workspaces/${selected}`, {
			action: 'provision',
			revision: snapshot.revision,
			recipient,
			publicKey: member.publicKey,
			wrappedKey,
			identityBinding
		});
		verifiedFingerprint = '';
		recipientId = '';
		await loadWorkspace();
	}
	async function manage(action: string, userId: string, role?: string) {
		if (!snapshot) return;
		if (
			action === 'remove-member' &&
			!confirm('Remove this member? New writes will pause until you rotate workspace keys.')
		)
			return;
		await api(`/api/workspaces/${selected}`, { action, revision: snapshot.revision, userId, role });
		await loadWorkspaces();
	}
</script>

<svelte:head><title>Workspaces · VOE</title></svelte:head>
<div class="p-4 sm:p-6 lg:p-8">
	<div class="flex flex-wrap items-start justify-between gap-4">
		<div>
			<h2 class="text-2xl font-semibold tracking-tight">Workspaces</h2>
			<p class="mt-1 text-sm text-muted-foreground">Shared secrets, encrypted on your device.</p>
		</div>
		<div class="flex gap-2">
			<Button
				variant="outline"
				onclick={() => {
					settings = !settings;
					if (settings) run(loadAccountSettings);
				}}>Settings</Button
			>{#if $isUnlocked}<Button variant="outline" onclick={lock}>Lock vault</Button>{/if}
		</div>
	</div>
	{#if error}<p
			role="alert"
			class="mt-5 rounded border border-destructive/30 p-3 text-sm text-destructive"
		>
			{error}
		</p>{/if}
	{#if notice}<p role="status" class="mt-5 text-sm">{notice}</p>{/if}
	<VaultAccess userId={data.user.id} onready={() => run(loadWorkspaces)} />
	{#if $isUnlocked}
		<div class="mt-6 flex flex-wrap gap-3">
			<label class="sr-only" for="workspace">Workspace</label><select
				id="workspace"
				class="h-10 min-w-52 rounded-md border bg-background px-3 text-sm"
				bind:value={selected}
				onchange={() => {
					folderId = '';
					run(loadWorkspace);
				}}
				disabled={busy}
				><option value="" disabled>Select workspace</option>{#each workspaces as ws}<option
						value={ws.id}>{ws.name}</option
					>{/each}</select
			><Button variant="outline" disabled={busy} onclick={() => run(loadWorkspaces)}>Refresh</Button
			>
		</div>
		{#if !workspaces.length || settings}<form
				class="mt-6 flex max-w-lg gap-2"
				onsubmit={(e) => {
					e.preventDefault();
					run(createWorkspace);
				}}
			>
				<Input
					aria-label="New workspace name"
					placeholder="New workspace name"
					bind:value={workspaceName}
					required
				/><Button type="submit" disabled={busy}>Create workspace</Button>
			</form>{/if}
		{#if snapshot}
			{#if !snapshot.folders.length}<div class="mt-8 rounded-xl border p-6">
					<h3 class="font-medium">Set up workspace encryption</h3>
					<p class="mt-2 text-sm text-muted-foreground">
						An owner needs to initialize this workspace.
					</p>
					{#if snapshot.role === 'owner'}<Button
							class="mt-4"
							disabled={busy}
							onclick={() =>
								run(async () => {
									await initializeWorkspace(selected);
									await loadWorkspace();
								})}>Initialize workspace</Button
						>{/if}
				</div>
			{:else if !snapshot.envelopes.length}<div class="mt-8 rounded-xl border p-6">
					<h3 class="font-medium">Awaiting key approval</h3>
					<p class="mt-2 text-sm text-muted-foreground">
						Ask an owner or admin to approve your encryption identity. Share your fingerprint
						through a trusted channel.
					</p>
					<code class="mt-4 block text-xs break-all select-all">{ownFingerprint}</code>
				</div>
			{:else}
				{#if snapshot.rotationRequired}<div class="mt-5 rounded border border-amber-500/40 p-4">
						<p class="text-sm">
							Access changed. Writes are paused until all workspace keys are replaced.
						</p>
						{#if canManage}<Button
								class="mt-3"
								disabled={busy}
								onclick={() =>
									run(async () => {
										await rotateWorkspace(snapshot!);
										await loadWorkspace();
									})}>Rotate keys and resume writes</Button
							>{/if}
					</div>{/if}
				<div class="mt-6 rounded-xl border">
					<div class="flex flex-wrap items-center justify-between gap-3 border-b p-4">
						<div class="flex items-center gap-3">
							{#if currentFolder?.parentId}<Button
									variant="ghost"
									size="sm"
									onclick={() => (folderId = currentFolder!.parentId!)}>← Back</Button
								>{/if}<span class="font-mono text-sm"
								>{currentFolder ? folderPath(snapshot.folders, folderId) || '/' : '/'}</span
							><span class="text-xs text-muted-foreground">{snapshot.role}</span>
						</div>
						<Button variant="ghost" size="sm" onclick={() => (revealed = !revealed)}
							>{revealed ? 'Hide values' : 'Show values'}</Button
						>
					</div>
					{#each snapshot.folders.filter((f) => f.parentId === folderId) as folder}<button
							class="flex w-full items-center justify-between border-b px-5 py-4 text-left text-sm hover:bg-muted/50"
							onclick={() => (folderId = folder.id)}
							><span>▸ {folder.name}</span><span class="text-muted-foreground">Folder</span></button
						>{/each}
					{#each snapshot.secrets.filter((s) => s.folderId === folderId) as secret}<div
							class="flex flex-wrap items-center gap-4 border-b px-5 py-4 last:border-b-0"
						>
							<span class="w-full font-mono text-sm sm:w-40 sm:shrink-0">{secret.name}</span><code
								class="min-w-0 basis-full text-xs break-all text-muted-foreground sm:flex-1 sm:basis-0"
								>{revealed ? (values[secret.id] ?? 'Locked') : '••••••••••••'}</code
							>{#if canWrite}<Button
									variant="ghost"
									size="sm"
									disabled={busy}
									onclick={() => {
										secretName = secret.name;
										secretValue = values[secret.id] || '';
									}}>Edit</Button
								><Button
									variant="ghost"
									size="sm"
									disabled={busy}
									onclick={() => run(() => deleteSecret(secret.id))}>Delete</Button
								>{/if}
						</div>{/each}
					{#if !snapshot.secrets.some((s) => s.folderId === folderId) && !snapshot.folders.some((f) => f.parentId === folderId)}<p
							class="p-8 text-center text-sm text-muted-foreground"
						>
							This folder is empty.
						</p>{/if}
				</div>
				{#if canWrite}<div class="mt-6 grid gap-5 lg:grid-cols-2">
						<form
							class="space-y-3 rounded-xl border p-5"
							onsubmit={(e) => {
								e.preventDefault();
								run(saveSecret);
							}}
						>
							<h3 class="text-sm font-medium">Add or update a secret</h3>
							<Input
								aria-label="Secret name"
								placeholder="DATABASE_URL"
								bind:value={secretName}
								required
								pattern="[A-Za-z_][A-Za-z0-9_]*"
							/><Input
								aria-label="Secret value"
								type="password"
								autocomplete="off"
								placeholder="Secret value"
								bind:value={secretValue}
							/><Button type="submit" disabled={busy}>Save secret</Button>
						</form>
						<form
							class="space-y-3 rounded-xl border p-5"
							onsubmit={(e) => {
								e.preventDefault();
								run(createFolder);
							}}
						>
							<h3 class="text-sm font-medium">New folder</h3>
							<Input
								aria-label="Folder name"
								placeholder="production"
								bind:value={folderName}
								required
								pattern="[^:]+"
							/><Button type="submit" variant="outline" disabled={busy}>Create folder</Button
							>{#if currentFolder?.parentId}<Button
									variant="ghost"
									disabled={busy}
									onclick={() => run(deleteFolder)}>Delete empty folder</Button
								>{/if}
						</form>
					</div>{/if}
			{/if}
		{/if}
		{#if settings}<section class="mt-8 space-y-6 rounded-xl border p-6">
				<h3 class="text-lg font-medium">Account and access</h3>
				<p class="text-sm text-muted-foreground">
					All members can read every folder in a workspace. Use separate workspaces for different
					audiences.
				</p>
				<div class="flex flex-wrap gap-2">
					<Button
						variant="outline"
						disabled={busy}
						onclick={() =>
							run(async () => {
								await addBackupPasskey();
								await loadAccountSettings();
								notice = 'Backup passkey enrolled for vault unlock.';
							})}>Add backup passkey</Button
					><Button variant="outline" href="/dashboard/migrate">Migrate legacy vaults</Button><Button
						variant="ghost"
						href="/dashboard/legacy">Legacy archive</Button
					>
				</div>
				<div>
					<p class="text-sm font-medium">Your identity fingerprint</p>
					<code class="mt-2 block text-xs break-all select-all">{ownFingerprint}</code>
				</div>
				<div class="space-y-3">
					<h4 class="font-medium">Passkeys</h4>
					{#each passkeys as credential}<div class="flex items-center justify-between gap-3">
							<span class="text-sm">{credential.name || 'Passkey'}</span><Button
								size="sm"
								variant="outline"
								disabled={busy}
								onclick={() =>
									run(async () => {
										if (
											!confirm(
												'Remove this passkey? Sessions authenticated with it will be signed out. Keep another passkey or your recovery key.'
											)
										)
											return;
										const result = await authClient.passkey.deletePasskey({ id: credential.id });
										if (result.error) throw new Error(result.error.message);
										lock();
										await loadAccountSettings();
									})}>Remove passkey</Button
							>
						</div>{/each}
				</div>
				<div class="space-y-3">
					<h4 class="font-medium">Your CLI devices</h4>
					{#each ownDevices.filter((d) => !d.revoked) as device}<div
							class="flex items-center justify-between gap-3"
						>
							<span class="font-mono text-xs">{device.id.slice(0, 8)}</span><Button
								size="sm"
								variant="outline"
								disabled={busy}
								onclick={() =>
									run(async () => {
										if (
											!confirm(
												'Revoke this device from every workspace? Administrators will need to rotate the affected workspace keys.'
											)
										)
											return;
										await api('/api/devices', { action: 'revoke', deviceId: device.id });
										await loadAccountSettings();
										await loadWorkspace();
									})}>Revoke everywhere</Button
							>
						</div>{/each}
				</div>
				{#if snapshot && canManage}<div class="border-t pt-6">
						<h4 class="font-medium">Members</h4>
						<form
							class="mt-4 flex flex-wrap gap-2"
							onsubmit={(e) => {
								e.preventDefault();
								run(invite);
							}}
						>
							<Input
								class="max-w-xs"
								aria-label="Invite email"
								type="email"
								placeholder="teammate@example.com"
								bind:value={email}
								required
							/><select
								aria-label="Invitation role"
								class="rounded border bg-background px-3 text-sm"
								bind:value={role}
								><option value="member">Member</option><option value="viewer">Viewer</option><option
									value="admin">Admin</option
								></select
							><Button type="submit" disabled={busy}>Invite</Button>
						</form>
						{#each snapshot.members as member}<div
								class="mt-4 flex flex-wrap items-center gap-3 rounded border p-3"
							>
								<div class="min-w-40 flex-1">
									<p class="text-sm">{member.name}</p>
									<p class="text-xs text-muted-foreground">
										{member.email} · {snapshot.recipients.includes(`user:${member.userId}`)
											? 'Key provisioned'
											: 'Awaiting key approval'}
									</p>
								</div>
								<select
									aria-label={`Role for ${member.email}`}
									class="rounded border bg-background px-2 py-1 text-sm"
									value={member.role}
									disabled={busy || (member.role === 'owner' && snapshot.role !== 'owner')}
									onchange={(e) => run(() => manage('role', member.userId, e.currentTarget.value))}
									><option value="viewer">Viewer</option><option value="member">Member</option
									><option value="admin">Admin</option
									>{#if snapshot.role === 'owner' || member.role === 'owner'}<option value="owner"
											>Owner</option
										>{/if}</select
								>{#if !snapshot.recipients.includes(`user:${member.userId}`)}<Button
										size="sm"
										variant="outline"
										disabled={!member.publicKey || busy}
										onclick={() => (recipientId = member.userId)}>Grant access</Button
									>{/if}<Button
									size="sm"
									variant="ghost"
									disabled={busy}
									onclick={() => run(() => manage('remove-member', member.userId))}>Remove</Button
								>
							</div>{/each}
						{#if recipientId}<form
								class="mt-4 space-y-3 rounded border p-4"
								onsubmit={(e) => {
									e.preventDefault();
									run(provision);
								}}
							>
								<p class="text-sm">
									Ask {snapshot.members.find((m) => m.userId === recipientId)?.email} for the fingerprint
									shown in their settings, using a trusted channel.
								</p>
								<Input
									aria-label="Verified member fingerprint"
									placeholder="Paste their full identity fingerprint"
									bind:value={verifiedFingerprint}
									required
								/><Button type="submit" disabled={busy}>Verify and grant access</Button>
							</form>{/if}
						{#each snapshot.devices.filter( (d) => snapshot!.recipients.includes(`device:${d.id}`) ) as device}<div
								class="mt-3 flex flex-wrap items-center justify-between gap-3 border-t pt-3"
							>
								<span class="text-xs"
									>CLI {device.id.slice(0, 8)} · {snapshot.members.find(
										(m) => m.userId === device.userId
									)?.email}</span
								><Button
									size="sm"
									variant="outline"
									disabled={busy}
									onclick={() =>
										run(async () => {
											if (!confirm('Revoke this device for this workspace?')) return;
											await api(`/api/workspaces/${selected}`, {
												action: 'revoke-device',
												revision: snapshot!.revision,
												deviceId: device.id
											});
											await loadWorkspace();
										})}>Revoke device</Button
								>
							</div>{/each}
					</div>{/if}
				{#if snapshot}<div class="space-y-3 border-t pt-5">
						<Button
							variant="outline"
							disabled={busy}
							onclick={() =>
								run(async () => {
									if (!confirm('Leave this workspace? An admin will need to invite you again.'))
										return;
									await api(`/api/workspaces/${selected}`, {
										action: 'leave',
										revision: snapshot!.revision
									});
									selected = '';
									snapshot = null;
									await loadWorkspaces();
								})}>Leave workspace</Button
						>{#if snapshot.role === 'owner'}<details>
								<summary class="cursor-pointer text-sm text-destructive">Delete workspace</summary>
								<p class="my-3 text-sm">
									Permanently delete all folders and secrets in this workspace. Type its name to
									confirm.
								</p>
								<Input aria-label="Workspace name to delete" bind:value={deleteName} /><Button
									class="mt-3"
									variant="destructive"
									disabled={busy || deleteName !== workspaces.find((w) => w.id === selected)?.name}
									onclick={() =>
										run(async () => {
											await api(`/api/workspaces/${selected}`, {
												action: 'delete-workspace',
												revision: snapshot!.revision,
												name: deleteName
											});
											selected = '';
											snapshot = null;
											deleteName = '';
											await loadWorkspaces();
										})}>Permanently delete workspace</Button
								>
							</details>{/if}
					</div>{/if}
			</section>{/if}
	{/if}
</div>
