<script lang="ts">
	import { authClient } from '#lib/auth-client.ts';
	import { Button } from '#lib/components/ui/button/index.ts';
	import { Input } from '#lib/components/ui/input/index.ts';
	import VaultAccess from '#lib/components/VaultAccess.svelte';
	import { api, isUnlocked, organizationKey, type Snapshot } from '#lib/vault-client.ts';
	import { wrapTo, seal, bytes } from '#lib/vault-crypto.ts';
	import { verifyDeviceFingerprint } from '#lib/device-approval.ts';
	import { orgContext, context } from '#lib/vault-format.ts';
	let { data } = $props();
	let enrollment = $state<{ id: string; publicKey: string } | null>(null);
	let workspaces = $state<{ id: string; name: string }[]>([]);
	let selected = $state<string[]>([]);
	let verified = $state('');
	let busy = $state(false);
	let error = $state('');
	let approved = $state(false);
	$effect(() => {
		const userCode = data.userCode;
		verified = data.deviceFingerprint;
		error = data.fingerprintError;
		enrollment = null;
		workspaces = [];
		selected = [];
		approved = false;
		if (!userCode || data.verificationError) return;
		let active = true;
		Promise.all([
			api<{ id: string; publicKey: string }>(`/api/devices?code=${encodeURIComponent(userCode)}`),
			api<{ id: string; name: string }[]>('/api/workspaces')
		])
			.then(([device, availableWorkspaces]) => {
				if (!active) return;
				enrollment = device;
				workspaces = availableWorkspaces;
			})
			.catch((e) => {
				if (active) error = (e as Error).message;
			});
		return () => {
			active = false;
		};
	});
	async function approve() {
		busy = true;
		error = '';
		try {
			if (!enrollment) throw new Error('Enrollment not found');
			await verifyDeviceFingerprint(verified, enrollment.publicKey);
			if (!selected.length) throw new Error('Choose at least one workspace to authorize.');
			const envelopes = [];
			for (const org of selected) {
				const snapshot = await api<Snapshot>(`/api/workspaces/${org}`);
				const key = await organizationKey(snapshot);
				const wrappedKey = await wrapTo(
					enrollment.publicKey,
					key,
					orgContext(org, `device:${enrollment.id}`, snapshot.epoch)
				);
				const identityBinding = await seal(
					key,
					bytes(enrollment.publicKey),
					context('recipient', org, `device:${enrollment.id}`, snapshot.epoch)
				);
				key.fill(0);
				envelopes.push({ organizationId: org, epoch: snapshot.epoch, wrappedKey, identityBinding });
			}
			await api('/api/devices', {
				deviceId: enrollment.id,
				publicKey: enrollment.publicKey,
				envelopes
			});
			const result = await authClient.device.approve({ userCode: data.userCode });
			if (result.error)
				throw new Error(result.error.error_description || 'Approval failed. Run ve auth again.');
			approved = true;
		} catch (e) {
			error = (e as Error).message;
		} finally {
			busy = false;
		}
	}
	async function deny() {
		const result = await authClient.device.deny({ userCode: data.userCode });
		if (result.error) error = result.error.error_description || 'Could not cancel';
		else location.href = '/dashboard/env';
	}
</script>

<svelte:head><title>Authorize CLI · VOE</title></svelte:head>
<main class="mx-auto max-w-xl px-6 py-16">
	<a href="/" class="text-xl font-semibold">voe.</a>{#if approved}<h1
			class="mt-10 text-2xl font-semibold"
		>
			Device authorized
		</h1>
		<p class="mt-4">Return to your terminal.</p>
		<Button class="mt-6" href="/dashboard/env">Open vault</Button>{:else if !data.userCode}<h1
			class="mt-10 text-2xl font-semibold"
		>
			Enter device code
		</h1>
		<form class="mt-6 flex gap-2" action="/device">
			{#if data.deviceFingerprint}<input
					type="hidden"
					name="fingerprint"
					value={data.deviceFingerprint}
				/>{/if}
			<Input name="user_code" aria-label="Device code" placeholder="ABCD-EFGH" required /><Button
				type="submit">Continue</Button
			>
		</form>{:else}<h1 class="mt-10 text-2xl font-semibold">Authorize this CLI</h1>
		<p class="mt-3 text-sm text-muted-foreground">
			Match the code, verify the device fingerprint, and choose which workspaces this device can
			decrypt.
		</p>
		<p class="my-6 rounded border p-4 text-center font-mono text-2xl">{data.userCode}</p>
		<VaultAccess userId={data.user.id} />{#if $isUnlocked && enrollment}<label
				class="block text-sm"
				for="device-fingerprint"
				>Device fingerprint from your terminal<Input
					class="mt-2"
					id="device-fingerprint"
					aria-describedby="fingerprint-help"
					autocomplete="off"
					spellcheck={false}
					placeholder="Paste the full fingerprint"
					bind:value={verified}
				/></label
			>
			<p id="fingerprint-help" class="mt-2 text-xs text-muted-foreground">
				{#if data.deviceFingerprint}
					Filled from your CLI link. Only authorize a sign-in you started in your terminal.
				{:else}
					Paste the full fingerprint shown by ve auth in your terminal.
				{/if}
			</p>
			<fieldset class="mt-6 space-y-3">
				<legend class="mb-3 text-sm font-medium">Workspace access</legend
				>{#each workspaces as workspace}<label class="flex gap-3 text-sm"
						><input
							type="checkbox"
							bind:group={selected}
							value={workspace.id}
						/>{workspace.name}</label
					>{/each}
			</fieldset>
			<Button class="mt-6 w-full" disabled={busy || !selected.length || !verified} onclick={approve}
				>Authorize device</Button
			>{/if}<Button class="mt-3 w-full" variant="ghost" disabled={busy} onclick={deny}
			>Cancel</Button
		>{/if}{#if error || data.verificationError}<p
			role="alert"
			class="mt-4 text-sm text-destructive"
		>
			{error || data.verificationError}
		</p>{/if}
	<p class="mt-8 text-xs text-muted-foreground">Signed in as {data.user.email}</p>
</main>
