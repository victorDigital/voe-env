<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import { Button } from '#lib/components/ui/button/index.ts';
	import { Input } from '#lib/components/ui/input/index.ts';
	import * as Dialog from '#lib/components/ui/dialog/index.ts';
	import {
		api,
		beginSetup,
		isUnlocked,
		signInAndUnlock,
		recover,
		type PendingSetup
	} from '#lib/vault-client.ts';
	let { userId, onready = () => {} }: { userId: string; onready?: () => void } = $props();
	let exists = $state<boolean | null>(null);
	let open = $state(false);
	$effect(() => {
		open = !$isUnlocked;
	});
	let busy = $state(false);
	let error = $state('');
	let recovery = $state('');
	let pending = $state<PendingSetup | null>(null);
	let confirm = $state('');
	let resetConfirmation = $state('');
	onMount(() => {
		api<{ identity: unknown }>('/api/identity')
			.then((r) => (exists = !!r.identity))
			.catch((e) => (error = e.message));
	});
	onDestroy(() => pending?.discard());
	async function run(action: () => Promise<void>) {
		busy = true;
		error = '';
		try {
			await action();
			if ($isUnlocked) onready();
		} catch (e) {
			error = (e as Error).message;
		} finally {
			busy = false;
		}
	}
	async function finish() {
		if (confirm.trim() !== pending?.recoveryKey)
			throw new Error('Paste your saved recovery key to verify the backup.');
		await pending.commit();
		pending = null;
		confirm = '';
		exists = true;
	}
</script>

<Dialog.Root
	bind:open
	onOpenChange={(value) => {
		if (!value) {
			recovery = '';
			confirm = '';
			resetConfirmation = '';
			error = '';
		}
	}}
>
	{#if !$isUnlocked}
		<Dialog.Trigger>
			{#snippet child({ props })}<Button {...props} variant="outline" class="mb-6"
					>{exists === false ? 'Set up vault' : 'Unlock vault'}</Button
				>{/snippet}
		</Dialog.Trigger>
	{/if}
	<Dialog.Content
		class="max-h-[calc(100dvh-2rem)] overflow-y-auto p-6 sm:max-w-md"
		showCloseButton={!busy}
		onEscapeKeydown={(event) => {
			if (busy) event.preventDefault();
		}}
		onInteractOutside={(event) => {
			if (busy) event.preventDefault();
		}}
	>
		<section aria-label="Unlock vault">
			<Dialog.Header>
				<Dialog.Title class="text-lg font-semibold tracking-tight">
					{pending
						? 'Save your recovery key'
						: exists
							? 'Unlock your vault'
							: 'Set up your encrypted vault'}
				</Dialog.Title>
				<Dialog.Description class="sr-only"
					>Unlock encrypted secrets with a passkey or recovery key.</Dialog.Description
				>
			</Dialog.Header>
			{#if pending}
				<p class="mt-3 text-xs leading-5 text-muted-foreground">
					Save this key somewhere safe, outside VOE. You will need it if you lose your passkeys. We
					cannot recover it for you.
				</p>
				<code class="my-5 block border bg-muted/20 p-4 text-xs leading-6 break-all select-all"
					>{pending.recoveryKey}</code
				>
				<label class="block text-xs" for="confirm-recovery"
					>Paste your saved key to verify your backup</label
				>
				<Input
					id="confirm-recovery"
					type="password"
					autocomplete="off"
					bind:value={confirm}
					class="mt-2"
				/>
				<Button class="mt-4 w-full" disabled={busy || !confirm} onclick={() => run(finish)}
					>Finish setup</Button
				>
			{:else if exists}
				<p class="mt-3 text-xs leading-5 text-muted-foreground">
					Use your passkey to decrypt secrets on this device.
				</p>
				<Button class="mt-6 w-full" disabled={busy} onclick={() => run(signInAndUnlock)}
					>{busy ? 'Unlocking…' : 'Unlock with passkey'}</Button
				>
				<details class="mt-5 text-xs">
					<summary class="cursor-pointer text-muted-foreground">Recover with an offline key</summary
					>
					<label class="mt-4 block" for="recovery-key">Recovery key</label><Input
						id="recovery-key"
						type="password"
						autocomplete="off"
						bind:value={recovery}
						class="mt-2"
					/>
					<Button
						class="mt-3"
						variant="outline"
						disabled={busy || !recovery}
						onclick={() =>
							run(async () => {
								await recover(recovery);
								recovery = '';
							})}>Recover vault</Button
					>
					<p class="mt-3 text-xs text-muted-foreground">
						Recovery signs out your other sessions. Add a replacement passkey after unlocking.
					</p>
				</details>
				<details class="mt-4 text-xs">
					<summary class="cursor-pointer text-muted-foreground"
						>Lost every passkey and recovery key?</summary
					>
					<p class="mt-3 text-xs leading-relaxed text-muted-foreground">
						Another provisioned owner or admin must be available in every workspace. Resetting
						removes your old passkeys and device access. After creating a new identity, share its
						fingerprint with an admin so they can rotate keys and approve it. Personal workspaces
						require the original recovery key.
					</p>
					<label class="mt-3 block" for="reset-identity">Type RESET to request a new identity</label
					><Input id="reset-identity" class="mt-2" bind:value={resetConfirmation} /><Button
						class="mt-3"
						variant="outline"
						disabled={busy || resetConfirmation !== 'RESET'}
						onclick={() =>
							run(async () => {
								await api('/api/identity', { action: 'reset', confirm: resetConfirmation });
								exists = false;
								resetConfirmation = '';
							})}>Reset identity for admin recovery</Button
					>
				</details>
			{:else if exists === false}
				<p class="mt-3 text-xs leading-5 text-muted-foreground">
					Create a passkey, then save an offline recovery key. Your passkey must support encryption
					unlock (WebAuthn PRF).
				</p>
				<Button
					class="mt-6 w-full"
					disabled={busy}
					onclick={() =>
						run(async () => {
							pending = await beginSetup(userId);
						})}>{busy ? 'Setting up…' : 'Create passkey'}</Button
				>
			{:else}<p class="mt-4 text-sm text-muted-foreground">Loading encryption settings…</p>{/if}
			{#if error}<p role="alert" class="mt-4 text-sm text-destructive">{error}</p>{/if}
		</section>
	</Dialog.Content>
</Dialog.Root>
