<script lang="ts">
	import type { Snippet } from 'svelte';
	import { Button } from '#lib/components/ui/button/index.ts';
	import VaultAccess from './VaultAccess.svelte';
	import {
		identity,
		isUnlocked,
		initializeWorkspace,
		rotateWorkspace,
		type Snapshot
	} from '#lib/vault-client.ts';
	import { fingerprint } from '#lib/vault-crypto.ts';
	import { permits } from '#lib/permissions.ts';
	import { useDashboard } from '#lib/dashboard.svelte.ts';
	let {
		userId,
		snapshot,
		refresh,
		children
	}: {
		userId: string;
		snapshot: Snapshot | null;
		refresh: () => Promise<void>;
		children: Snippet;
	} = $props();
	const dashboard = useDashboard();
	let identityFingerprint = $state('');
	let error = $state('');
	$effect(() => {
		let cancelled = false;
		if ($isUnlocked)
			fingerprint(identity().publicKey).then((value) => {
				if (!cancelled) identityFingerprint = value;
			});
		else identityFingerprint = '';
		return () => {
			cancelled = true;
		};
	});
	async function run(action: () => Promise<void>) {
		dashboard.working = true;
		error = '';
		try {
			await action();
			await refresh();
		} catch (e) {
			error = (e as Error).message;
		} finally {
			dashboard.working = false;
		}
	}
</script>

<VaultAccess {userId} onready={() => refresh()} />
{#if $isUnlocked}
	{#if error}<p role="alert" class="mb-5 text-xs text-destructive">{error}</p>{/if}
	{#if !dashboard.selected}
		<div class="flex min-h-80 flex-col items-center justify-center gap-4">
			<h2 class="text-base font-medium">Your first workspace</h2>
			<Button onclick={() => (dashboard.createOpen = true)}>Create workspace</Button>
		</div>
	{:else if !snapshot}
		<div role="status" class="py-16 text-center text-xs text-muted-foreground">
			Loading workspace…
		</div>
	{:else if !snapshot.folders.length}
		<div class="mx-auto max-w-md py-16 text-center">
			<h2 class="text-base font-medium">Set up workspace</h2>
			<p class="mt-2 text-xs text-muted-foreground">An owner needs to enable encryption.</p>
			{#if snapshot.role === 'owner'}<Button
					class="mt-5"
					disabled={dashboard.working}
					onclick={() => run(() => initializeWorkspace(snapshot!.organizationId))}
					>Initialize workspace</Button
				>{/if}
		</div>
	{:else if !snapshot.envelopes.length}
		<div class="mx-auto max-w-md py-16">
			<h2 class="text-base font-medium">Awaiting access</h2>
			<p class="mt-2 text-sm text-muted-foreground">
				Send this fingerprint to an admin through a trusted channel.
			</p>
			<code class="mt-5 block border bg-muted/20 p-4 text-xs leading-6 break-all select-all"
				>{identityFingerprint}</code
			><Button class="mt-4" variant="outline" onclick={() => refresh()}>Check access</Button>
		</div>
	{:else}
		{#if snapshot.rotationRequired}<div
				class="mb-6 flex flex-wrap items-center justify-between gap-3 border-l-2 border-amber-500 bg-amber-500/5 px-4 py-3"
			>
				<p class="text-xs">Access changed. Rotate keys to resume editing.</p>
				{#if permits(snapshot.role, 'provision')}<Button
						variant="outline"
						size="sm"
						disabled={dashboard.working}
						onclick={() => run(() => rotateWorkspace(snapshot!))}>Rotate keys</Button
					>{/if}
			</div>{/if}
		{@render children()}
	{/if}
{/if}
