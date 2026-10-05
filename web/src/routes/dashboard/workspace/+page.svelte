<script lang="ts">
	import ActionError from '#lib/components/ActionError.svelte';
	import DeviceLastUsed from '#lib/components/DeviceLastUsed.svelte';
	import { untrack, onDestroy } from 'svelte';
	import { goto } from '$app/navigation';
	import { Button } from '#lib/components/ui/button/index.ts';
	import { Input } from '#lib/components/ui/input/index.ts';
	import { Label } from '#lib/components/ui/label/index.ts';
	import * as Select from '#lib/components/ui/select/index.ts';
	import * as Dialog from '#lib/components/ui/dialog/index.ts';
	import * as DropdownMenu from '#lib/components/ui/dropdown-menu/index.ts';
	import WorkspaceAccess from '#lib/components/WorkspaceAccess.svelte';
	import ConfirmAction from '#lib/components/ConfirmAction.svelte';
	import { useDashboard } from '#lib/dashboard.svelte.ts';
	import {
		api,
		organizationKey,
		isUnlocked,
		signInAndUnlock,
		type Snapshot
	} from '#lib/vault-client.ts';
	import { authClient } from '#lib/auth-client.ts';
	import { fingerprint, seal, bytes, wrapTo } from '#lib/vault-crypto.ts';
	import { context, orgContext } from '#lib/vault-format.ts';
	import { permits } from '#lib/permissions.ts';
	import RiAddLine from 'remixicon-svelte/icons/add-line';
	import RiMoreLine from 'remixicon-svelte/icons/more-line';
	import RiComputerLine from 'remixicon-svelte/icons/computer-line';
	let { data } = $props();
	const dashboard = useDashboard();
	let selected = $derived(dashboard.selected);
	let snapshot = $state<Snapshot | null>(null);
	let busy = $derived(dashboard.working);
	let error = $state('');
	let notice = $state('');
	let invitations = $state<
		{ id: string; email: string; role: string | null; status: string; expiresAt: Date | string }[]
	>([]);
	let inviteOpen = $state(false);
	let email = $state('');
	let role = $state<'admin' | 'member' | 'viewer'>('member');
	let recipientId = $state('');
	let grantOpen = $state(false);
	let verifiedFingerprint = $state('');
	let deleteOpen = $state(false);
	let deleteName = $state('');
	let confirmOpen = $state(false);
	let confirmation = $state<{
		title: string;
		description: string;
		label: string;
		action: () => Promise<void>;
	} | null>(null);
	let requestId = 0;
	let canManage = $derived(!!snapshot && permits(snapshot.role, 'provision'));
	let pending = $derived(
		invitations.filter((i) => i.status === 'pending' && new Date(i.expiresAt) > new Date())
	);
	const roleName = (value: string) => value.charAt(0).toUpperCase() + value.slice(1);
	$effect(() => {
		selected;
		dashboard.revision;
		untrack(load);
	});
	onDestroy(() => {
		requestId++;
	});
	async function load() {
		const id = selected,
			request = ++requestId;
		error = '';
		if (snapshot?.organizationId !== id) {
			snapshot = null;
			invitations = [];
		}
		if (!id) return;
		try {
			const next = await api<Snapshot>(`/api/workspaces/${id}`);
			if (request !== requestId) return;
			snapshot = next;
			if (permits(next.role, 'provision')) {
				const result = await authClient.organization.listInvitations({
					query: { organizationId: id }
				});
				if (result.error) throw new Error(result.error.message);
				if (request === requestId) invitations = result.data || [];
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
			if (!$isUnlocked) await signInAndUnlock();
			await action();
		} catch (e) {
			error = (e as Error).message;
		} finally {
			dashboard.working = false;
		}
	}
	function confirm(title: string, description: string, label: string, action: () => Promise<void>) {
		confirmation = { title, description, label, action };
		confirmOpen = true;
	}
	async function manage(action: string, fields: Record<string, unknown> = {}) {
		if (!snapshot) return;
		await api(`/api/workspaces/${snapshot.organizationId}`, {
			action,
			revision: snapshot.revision,
			...fields
		});
		await load();
	}
	async function invite() {
		const result = await authClient.organization.inviteMember({
			organizationId: selected,
			email: email.trim(),
			role
		});
		if (result.error) throw new Error(result.error.message);
		email = '';
		inviteOpen = false;
		await load();
		notice = 'Invitation sent.';
	}
	async function provision() {
		if (!snapshot) return;
		const member = snapshot.members.find((m) => m.userId === recipientId);
		if (!member?.publicKey) throw new Error('This member must finish vault setup first.');
		if (
			verifiedFingerprint.trim().toLowerCase().replace(/\s/g, '') !==
			(await fingerprint(member.publicKey))
		)
			throw new Error(
				'Fingerprint does not match. Confirm it with the member through a trusted channel.'
			);
		const key = await organizationKey(snapshot);
		const recipient = `user:${member.userId}`;
		try {
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
			await manage('provision', {
				recipient,
				publicKey: member.publicKey,
				wrappedKey,
				identityBinding
			});
		} finally {
			key.fill(0);
		}
		grantOpen = false;
		verifiedFingerprint = '';
		recipientId = '';
	}
	async function leaveOrDelete(action: string) {
		if (!snapshot) return;
		await api(`/api/workspaces/${snapshot.organizationId}`, {
			action,
			revision: snapshot.revision,
			name: deleteName
		});
		deleteOpen = false;
		confirmOpen = false;
		snapshot = null;
		await dashboard.refresh();
		await goto('/dashboard/env');
	}
</script>

<svelte:head><title>Workspace settings · VOE</title></svelte:head>
<div class="mx-auto w-full max-w-4xl px-4 py-8 sm:px-8 lg:py-10">
	<div class="mb-8">
		<h1 class="text-xl font-semibold tracking-tight">{dashboard.workspace?.name || 'Workspace'}</h1>
		<p class="mt-1.5 text-xs text-muted-foreground">Workspace settings</p>
	</div>
	{#if error && !inviteOpen && !grantOpen && !deleteOpen}<p
			role="alert"
			class="mb-5 text-xs text-destructive"
		>
			{error}
		</p>{/if}
	{#if notice}<p role="status" class="mb-5 text-xs text-muted-foreground">{notice}</p>{/if}
	<WorkspaceAccess userId={data.user.id} {snapshot} refresh={load} requireUnlock={false}>
		<section aria-labelledby="members-heading" class="mb-10">
			<div class="mb-4 flex items-center justify-between gap-4">
				<div>
					<h2 id="members-heading" class="text-sm font-medium">
						Members <span class="ml-1 text-muted-foreground">{snapshot?.members.length}</span>
					</h2>
					<p class="mt-1 text-xs text-muted-foreground">
						Members can access every folder in this workspace.
					</p>
				</div>
				{#if canManage}<Button
						size="sm"
						disabled={busy}
						onclick={() => {
							inviteOpen = true;
							error = '';
						}}><RiAddLine />Invite member</Button
					>{/if}
			</div>
			<div class="divide-y border-y">
				{#each snapshot?.members || [] as member}<div
						class="flex flex-wrap items-center gap-3 py-4"
					>
						<span
							class="flex size-8 shrink-0 items-center justify-center border text-xs text-muted-foreground"
							>{(member.name || member.email).slice(0, 1).toUpperCase()}</span
						>
						<div class="min-w-0 flex-1">
							<p class="truncate text-xs font-medium">
								{member.name || member.email}{#if member.userId === data.user.id}<span
										class="ml-1 text-muted-foreground">(you)</span
									>{/if}
							</p>
							<p class="mt-1 truncate text-[11px] text-muted-foreground">{member.email}</p>
							{#if !snapshot?.recipients.includes(`user:${member.userId}`)}<p
									class="mt-1 text-[11px] text-amber-600 dark:text-amber-400"
								>
									{member.publicKey ? 'Awaiting access' : 'Vault setup pending'}
								</p>{/if}
						</div>
						{#if canManage}<div class="flex items-center gap-1">
								<Select.Root
									type="single"
									value={member.role}
									onValueChange={(value) => {
										if (value !== member.role)
											run(() => manage('role', { userId: member.userId, role: value }));
									}}
									disabled={busy ||
										member.userId === data.user.id ||
										(member.role === 'owner' && snapshot?.role !== 'owner')}
									><Select.Trigger
										aria-label={`Role for ${member.email}`}
										class="w-24 border-transparent bg-transparent!"
										>{roleName(member.role)}</Select.Trigger
									><Select.Content
										><Select.Item value="viewer" label="Viewer">Viewer</Select.Item><Select.Item
											value="member"
											label="Member">Member</Select.Item
										><Select.Item value="admin" label="Admin">Admin</Select.Item
										>{#if snapshot?.role === 'owner' || member.role === 'owner'}<Select.Item
												value="owner"
												label="Owner">Owner</Select.Item
											>{/if}</Select.Content
									></Select.Root
								>
								<DropdownMenu.Root
									><DropdownMenu.Trigger
										aria-label={`Manage ${member.email}`}
										disabled={busy}
										class="inline-flex size-8 items-center justify-center hover:bg-muted"
										><RiMoreLine class="size-4" /></DropdownMenu.Trigger
									><DropdownMenu.Content align="end"
										>{#if !snapshot?.recipients.includes(`user:${member.userId}`)}<DropdownMenu.Item
												disabled={!member.publicKey}
												onSelect={() => {
													recipientId = member.userId;
													verifiedFingerprint = '';
													error = '';
													grantOpen = true;
												}}>Grant encryption access</DropdownMenu.Item
											><DropdownMenu.Separator />{/if}<DropdownMenu.Item
											variant="destructive"
											disabled={member.userId === data.user.id ||
												(member.role === 'owner' && snapshot?.role !== 'owner')}
											onSelect={() =>
												confirm(
													`Remove ${member.name || member.email}?`,
													'They will lose workspace access. Rotate keys afterward to resume editing.',
													'Remove member',
													() => manage('remove-member', { userId: member.userId })
												)}>Remove member</DropdownMenu.Item
										></DropdownMenu.Content
									></DropdownMenu.Root
								>
							</div>{:else}<span class="text-xs text-muted-foreground">{roleName(member.role)}</span
							>{/if}
					</div>{/each}
			</div>
		</section>
		{#if canManage && pending.length}<section class="mb-10">
				<h2 class="mb-4 text-sm font-medium">Pending invitations</h2>
				<div class="divide-y border-y">
					{#each pending as invitation}<div class="flex items-center gap-3 py-4">
							<div class="min-w-0 flex-1">
								<p class="truncate text-xs">{invitation.email}</p>
								<p class="mt-1 text-[11px] text-muted-foreground">
									{roleName(invitation.role || 'member')}
								</p>
							</div>
							<Button
								variant="ghost"
								size="sm"
								disabled={busy}
								onclick={() =>
									run(async () => {
										const result = await authClient.organization.cancelInvitation({
											invitationId: invitation.id
										});
										if (result.error) throw new Error(result.error.message);
										await load();
									})}>Cancel invite</Button
							>
						</div>{/each}
				</div>
			</section>{/if}
		{#if canManage}<section class="mb-10">
				<h2 class="mb-4 text-sm font-medium">Workspace devices</h2>
				<div class="divide-y border-y">
					{#each snapshot?.devices.filter( (d) => snapshot?.recipients.includes(`device:${d.id}`) ) || [] as device}<div
							class="flex items-center gap-3 py-4"
						>
							<RiComputerLine class="size-4 shrink-0 text-muted-foreground" />
							<div class="min-w-0 flex-1">
								<p class="text-xs">
									CLI <span class="font-mono text-muted-foreground">{device.id.slice(0, 8)}</span>
								</p>
								<p class="mt-1 truncate text-[11px] text-muted-foreground">
									{snapshot?.members.find((m) => m.userId === device.userId)?.email}
								</p>
								<DeviceLastUsed value={device.lastUsedAt} />
							</div>
							<Button
								variant="outline"
								size="sm"
								disabled={busy}
								onclick={() =>
									confirm(
										'Revoke device access?',
										'This removes the device from this workspace. Rotate keys afterward to resume editing.',
										'Revoke access',
										() => manage('revoke-device', { deviceId: device.id })
									)}>Revoke access</Button
							>
						</div>{:else}<p class="py-6 text-xs text-muted-foreground">
							No approved devices.
						</p>{/each}
				</div>
			</section>{/if}
		<section class="space-y-5 border-t pt-6">
			<div class="flex items-center justify-between gap-4">
				<div>
					<h2 class="text-xs font-medium">Leave workspace</h2>
					<p class="mt-1 text-[11px] text-muted-foreground">
						An admin will need to invite you back.
					</p>
				</div>
				<Button
					variant="outline"
					size="sm"
					disabled={busy}
					onclick={() =>
						confirm(
							'Leave workspace?',
							'You will lose access to its folders and secrets.',
							'Leave workspace',
							() => leaveOrDelete('leave')
						)}>Leave</Button
				>
			</div>
			{#if snapshot?.role === 'owner'}<div class="flex items-center justify-between gap-4">
					<div>
						<h2 class="text-xs font-medium">Delete workspace</h2>
						<p class="mt-1 text-[11px] text-muted-foreground">
							Permanently remove all folders and secrets.
						</p>
					</div>
					<Button
						variant="ghost"
						size="sm"
						class="text-destructive"
						disabled={busy}
						onclick={() => {
							deleteName = '';
							deleteOpen = true;
							error = '';
						}}>Delete</Button
					>
				</div>{/if}
		</section>
	</WorkspaceAccess>
</div>
<Dialog.Root bind:open={inviteOpen}
	><Dialog.Content class="p-6 sm:max-w-md"
		><Dialog.Header
			><Dialog.Title>Invite member</Dialog.Title><Dialog.Description
				>Invite someone to {dashboard.workspace?.name}.</Dialog.Description
			></Dialog.Header
		>
		<form
			class="space-y-5"
			onsubmit={(e) => {
				e.preventDefault();
				run(invite);
			}}
		>
			<div class="space-y-2">
				<Label for="invite-email">Email</Label><Input
					id="invite-email"
					type="email"
					bind:value={email}
					placeholder="name@company.com"
					required
				/>
			</div>
			<div class="space-y-2">
				<Label for="invite-role">Role</Label><Select.Root type="single" bind:value={role}
					><Select.Trigger id="invite-role" class="w-full">{roleName(role)}</Select.Trigger
					><Select.Content
						><Select.Item value="member" label="Member">Member</Select.Item><Select.Item
							value="viewer"
							label="Viewer">Viewer</Select.Item
						><Select.Item value="admin" label="Admin">Admin</Select.Item></Select.Content
					></Select.Root
				>
				<p class="text-[11px] text-muted-foreground">
					{role === 'viewer'
						? 'Can read secrets.'
						: role === 'admin'
							? 'Can edit secrets and manage members.'
							: 'Can read and edit secrets.'}
				</p>
			</div>
			<ActionError bind:error /><Dialog.Footer
				><Button variant="outline" disabled={busy} onclick={() => (inviteOpen = false)}
					>Cancel</Button
				><Button type="submit" disabled={busy}>{busy ? 'Sending…' : 'Send invitation'}</Button
				></Dialog.Footer
			>
		</form></Dialog.Content
	></Dialog.Root
>
<Dialog.Root bind:open={grantOpen}
	><Dialog.Content class="p-6 sm:max-w-md"
		><Dialog.Header
			><Dialog.Title>Grant encryption access</Dialog.Title><Dialog.Description
				>Ask {snapshot?.members.find((m) => m.userId === recipientId)?.email} for their identity fingerprint
				through a trusted channel.</Dialog.Description
			></Dialog.Header
		>
		<form
			class="space-y-5"
			onsubmit={(e) => {
				e.preventDefault();
				run(provision);
			}}
		>
			<div class="space-y-2">
				<Label for="member-fingerprint">Identity fingerprint</Label><Input
					id="member-fingerprint"
					class="font-mono"
					bind:value={verifiedFingerprint}
					required
					placeholder="Paste the full fingerprint"
				/>
			</div>
			<ActionError bind:error /><Dialog.Footer
				><Button variant="outline" disabled={busy} onclick={() => (grantOpen = false)}
					>Cancel</Button
				><Button type="submit" disabled={busy}>Verify and grant access</Button></Dialog.Footer
			>
		</form></Dialog.Content
	></Dialog.Root
>
<Dialog.Root bind:open={deleteOpen}
	><Dialog.Content class="p-6 sm:max-w-md"
		><Dialog.Header
			><Dialog.Title>Delete workspace</Dialog.Title><Dialog.Description
				>All folders and secrets will be permanently deleted.</Dialog.Description
			></Dialog.Header
		>
		<form
			class="space-y-5"
			onsubmit={(e) => {
				e.preventDefault();
				run(() => leaveOrDelete('delete-workspace'));
			}}
		>
			<div class="space-y-2">
				<Label for="delete-name">Type {dashboard.workspace?.name} to confirm</Label><Input
					id="delete-name"
					bind:value={deleteName}
					autocomplete="off"
				/>
			</div>
			<ActionError bind:error /><Dialog.Footer
				><Button variant="outline" disabled={busy} onclick={() => (deleteOpen = false)}
					>Cancel</Button
				><Button
					type="submit"
					variant="destructive"
					disabled={busy || deleteName !== dashboard.workspace?.name}>Delete workspace</Button
				></Dialog.Footer
			>
		</form></Dialog.Content
	></Dialog.Root
>
<ConfirmAction
	bind:error
	bind:open={confirmOpen}
	title={confirmation?.title || ''}
	description={confirmation?.description || ''}
	label={confirmation?.label || 'Confirm'}
	{busy}
	onconfirm={() =>
		run(async () => {
			await confirmation?.action();
			confirmOpen = false;
		})}
/>
