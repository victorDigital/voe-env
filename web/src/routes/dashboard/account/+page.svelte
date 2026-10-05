<script lang="ts">
	import { onMount } from 'svelte';
	import DeviceLastUsed from '#lib/components/DeviceLastUsed.svelte';
	import { Button } from '#lib/components/ui/button/index.ts';
	import * as Dialog from '#lib/components/ui/dialog/index.ts';
	import VaultAccess from '#lib/components/VaultAccess.svelte';
	import ConfirmAction from '#lib/components/ConfirmAction.svelte';
	import { authClient } from '#lib/auth-client.ts';
	import { api, addBackupPasskey, identity, isUnlocked, lock } from '#lib/vault-client.ts';
	import { fingerprint } from '#lib/vault-crypto.ts';
	import { useDashboard } from '#lib/dashboard.svelte.ts';
	import RiComputerLine from 'remixicon-svelte/icons/computer-line';
	import RiKey2Line from 'remixicon-svelte/icons/key-2-line';
	import RiAddLine from 'remixicon-svelte/icons/add-line';
	import RiFileCopyLine from 'remixicon-svelte/icons/file-copy-line';
	let { data } = $props();
	const dashboard = useDashboard();
	let devices = $state<
		{
			id: string;
			revoked: boolean;
			createdAt: string;
			lastUsedAt: string | null;
			publicKey: string;
		}[]
	>([]);
	let passkeys = $state<{ id: string; name?: string | null; createdAt?: Date | null }[]>([]);
	let ownFingerprint = $state('');
	let busy = $state(false);
	let loaded = $state(false);
	let error = $state('');
	let notice = $state('');
	let confirmOpen = $state(false);
	let removal = $state<{ id: string; kind: 'device' | 'passkey' } | null>(null);
	let detail = $state<{ id: string; fingerprint: string } | null>(null);
	let detailOpen = $state(false);
	const date = (value: string | Date | null | undefined) =>
		value
			? new Date(value).toLocaleDateString(undefined, {
					month: 'short',
					day: 'numeric',
					year: 'numeric'
				})
			: '';
	onMount(() => {
		run(load);
	});
	$effect(() => {
		let cancelled = false;
		if ($isUnlocked)
			fingerprint(identity().publicKey).then((value) => {
				if (!cancelled) ownFingerprint = value;
			});
		else ownFingerprint = '';
		return () => {
			cancelled = true;
		};
	});
	async function load() {
		const [keys, nextDevices] = await Promise.all([
			authClient.passkey.listUserPasskeys(),
			api<typeof devices>('/api/devices')
		]);
		if (keys.error) throw new Error(keys.error.message);
		passkeys = keys.data || [];
		devices = nextDevices;
		loaded = true;
	}
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
	async function remove() {
		if (!removal) return;
		if (removal.kind === 'device') {
			await api('/api/devices', { action: 'revoke', deviceId: removal.id });
			await dashboard.refresh();
			notice = 'Device revoked. Rotate keys in affected workspaces.';
		} else {
			const result = await authClient.passkey.deletePasskey({ id: removal.id });
			if (result.error) throw new Error(result.error.message);
			lock();
		}
		confirmOpen = false;
		await load();
	}
</script>

<svelte:head><title>Account settings · VOE</title></svelte:head>
<div class="mx-auto w-full max-w-4xl px-4 py-8 sm:px-8 lg:py-10">
	<div class="mb-8">
		<h1 class="text-xl font-semibold tracking-tight">Account</h1>
		<p class="mt-1.5 text-xs text-muted-foreground">{data.user.email}</p>
	</div>
	<VaultAccess userId={data.user.id} onready={() => run(load)} />
	{#if error}<p role="alert" class="mb-5 text-xs text-destructive">{error}</p>{/if}
	{#if notice}<p role="status" class="mb-5 text-xs text-muted-foreground">{notice}</p>{/if}
	<section aria-labelledby="devices-heading" class="mb-10">
		<div class="mb-4">
			<h2 id="devices-heading" class="text-sm font-medium">Your devices</h2>
			<p class="mt-1 text-xs text-muted-foreground">Devices approved to access your workspaces.</p>
		</div>
		<div class="divide-y border-y">
			{#each devices.filter((d) => !d.revoked) as device}<div class="flex items-center gap-3 py-4">
					<RiComputerLine class="size-4 shrink-0 text-muted-foreground" /><button
						class="min-w-0 flex-1 text-left"
						onclick={() =>
							run(async () => {
								detail = { id: device.id, fingerprint: await fingerprint(device.publicKey) };
								detailOpen = true;
							})}
						><span class="block text-xs font-medium"
							>CLI device <span class="ml-1 font-mono text-muted-foreground"
								>{device.id.slice(0, 8)}</span
							></span
						><span class="mt-1 block text-[11px] text-muted-foreground"
							>Added {date(device.createdAt)}</span
						><DeviceLastUsed value={device.lastUsedAt} /></button
					><Button
						variant="outline"
						size="sm"
						disabled={busy || !$isUnlocked}
						onclick={() => {
							removal = { id: device.id, kind: 'device' };
							confirmOpen = true;
						}}>Revoke access</Button
					>
				</div>{:else}<p class="py-8 text-xs text-muted-foreground">
					{loaded ? 'No approved devices.' : 'Loading devices…'}
				</p>{/each}
		</div>
	</section>
	<section aria-labelledby="passkeys-heading" class="mb-10">
		<div class="mb-4 flex items-center justify-between gap-3">
			<div>
				<h2 id="passkeys-heading" class="text-sm font-medium">Passkeys</h2>
				<p class="mt-1 text-xs text-muted-foreground">Sign in and unlock your vault.</p>
			</div>
			<Button
				variant="outline"
				size="sm"
				disabled={busy || !$isUnlocked}
				onclick={() =>
					run(async () => {
						await addBackupPasskey();
						await load();
						notice = 'Passkey added.';
					})}><RiAddLine />Add passkey</Button
			>
		</div>
		<div class="divide-y border-y">
			{#each passkeys as credential}<div class="flex items-center gap-3 py-4">
					<RiKey2Line class="size-4 shrink-0 text-muted-foreground" />
					<div class="min-w-0 flex-1">
						<p class="truncate text-xs font-medium">{credential.name || 'Passkey'}</p>
						<p class="mt-1 text-[11px] text-muted-foreground">{date(credential.createdAt)}</p>
					</div>
					<Button
						variant="ghost"
						size="sm"
						disabled={busy || !$isUnlocked}
						onclick={() => {
							removal = { id: credential.id, kind: 'passkey' };
							confirmOpen = true;
						}}>Remove</Button
					>
				</div>{:else}<p class="py-8 text-xs text-muted-foreground">
					{loaded ? 'No passkeys.' : 'Loading passkeys…'}
				</p>{/each}
		</div>
	</section>
	{#if ownFingerprint}<section class="mb-10">
			<h2 class="text-sm font-medium">Identity fingerprint</h2>
			<p class="mt-1 text-xs text-muted-foreground">
				Share with an admin to verify your workspace access.
			</p>
			<div class="mt-4 flex items-center gap-3 border bg-muted/20 p-3">
				<code class="min-w-0 flex-1 text-[11px] leading-5 break-all select-all"
					>{ownFingerprint}</code
				><Button
					variant="ghost"
					size="icon-sm"
					aria-label="Copy identity fingerprint"
					onclick={() =>
						run(async () => {
							await navigator.clipboard.writeText(ownFingerprint);
							notice = 'Fingerprint copied.';
						})}><RiFileCopyLine /></Button
				>
			</div>
		</section>{/if}
</div>
<ConfirmAction
	bind:error
	bind:open={confirmOpen}
	title={removal?.kind === 'device' ? 'Revoke device access?' : 'Remove passkey?'}
	description={removal?.kind === 'device'
		? 'This device will lose access to every workspace. A workspace admin must then rotate its keys.'
		: 'Sessions using this passkey will be signed out. Keep another passkey or your recovery key.'}
	label={removal?.kind === 'device' ? 'Revoke access' : 'Remove passkey'}
	{busy}
	onconfirm={() => run(remove)}
/>
<Dialog.Root bind:open={detailOpen}
	><Dialog.Content class="p-6 sm:max-w-md"
		><Dialog.Header
			><Dialog.Title>CLI device</Dialog.Title><Dialog.Description
				>Compare this fingerprint with your CLI enrollment.</Dialog.Description
			></Dialog.Header
		><code class="border bg-muted/20 p-3 text-xs leading-6 break-all select-all"
			>{detail?.fingerprint}</code
		>
		<p class="text-[11px] break-all text-muted-foreground">{detail?.id}</p></Dialog.Content
	></Dialog.Root
>
