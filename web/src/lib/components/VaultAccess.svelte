<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import { Button } from '#lib/components/ui/button/index.ts';
	import { Input } from '#lib/components/ui/input/index.ts';
	import * as Dialog from '#lib/components/ui/dialog/index.ts';
	import RiKey2Line from 'remixicon-svelte/icons/key-2-line';
	import {
		api,
		beginSetup,
		isUnlocked,
		signInAndUnlock,
		recover,
		type PendingSetup
	} from '#lib/vault-client.ts';
	let {
		userId,
		onready = () => {},
		autoOpen = true,
		screen = false
	}: { userId: string; onready?: () => void; autoOpen?: boolean; screen?: boolean } = $props();
	let exists = $state<boolean | null>(null);
	let open = $state(false);
	$effect(() => {
		if ($isUnlocked) open = false;
		else if (autoOpen) open = true;
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
		if (busy) return;
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

{#snippet unlockButton()}
	<Dialog.Trigger
		onclick={() => {
			if (exists) run(signInAndUnlock);
		}}
	>
		{#snippet child({ props })}<Button
				{...props}
				variant={screen ? 'default' : 'outline'}
				class={screen ? 'mt-6 h-9 gap-2 px-4' : 'mb-6'}
				disabled={busy || exists === null}
				>{#if screen}<RiKey2Line />{/if}{busy
					? 'Unlocking…'
					: exists === false
						? 'Set up vault'
						: 'Unlock vault'}</Button
			>{/snippet}
	</Dialog.Trigger>
{/snippet}

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
		{#if screen}
			<section
				aria-labelledby="vault-locked-title"
				class="vault-locked relative flex min-h-96 flex-1 flex-col items-center justify-center overflow-hidden px-6 py-16 text-center"
			>
				<div aria-hidden="true" class="vault-grid pointer-events-none absolute inset-0"></div>
				<div class="relative flex flex-col items-center">
					<svg
						aria-hidden="true"
						focusable="false"
						class="vault-circuit mb-6 size-40"
						viewBox="0 0 160 160"
						fill="none"
					>
						<g stroke="currentColor" stroke-width="1">
							<path opacity="0.25" d="M52 14H108L146 52V108L108 146H52L14 108V52Z" />
							<path opacity="0.5" d="M57 27H103L133 57V103L103 133H57L27 103V57Z" />
							<path
								d="M0 80H27M133 80H160M80 0V27M80 133V160M14 48V14H48M112 14H146V48M146 112V146H112M48 146H14V112"
							/>
							<path stroke-width="2" d="M65 72V59A15 15 0 0 1 95 59V72M58 72H102V106H58Z" />
							<path stroke-width="2" d="M80 88V96" />
						</g>
						<circle cx="80" cy="85" r="3" fill="currentColor" />
						<path
							d="M78 12H82V16H78ZM144 78H148V82H144ZM78 144H82V148H78ZM12 78H16V82H12Z"
							fill="currentColor"
						/>
					</svg>
					<p class="mb-2 font-mono text-[10px] tracking-[0.2em] text-muted-foreground uppercase">
						Encrypted vault
					</p>
					<h1 id="vault-locked-title" class="text-xl font-medium tracking-tight">
						{exists === false ? 'Set up your vault' : 'Vault locked'}
					</h1>
					{@render unlockButton()}
				</div>
			</section>
		{:else}
			{@render unlockButton()}
		{/if}
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

<style>
	.vault-locked {
		--vault-signal: oklch(0.48 0.09 195);
		background: radial-gradient(
			ellipse 280px 220px at center,
			color-mix(in oklch, var(--vault-signal) 7%, transparent),
			transparent
		);
	}
	:global(.dark) .vault-locked {
		--vault-signal: oklch(0.8 0.12 195);
	}
	.vault-circuit {
		color: var(--vault-signal);
	}
	.vault-grid {
		background-image:
			linear-gradient(
				color-mix(in oklch, var(--vault-signal) 8%, transparent) 1px,
				transparent 1px
			),
			linear-gradient(
				90deg,
				color-mix(in oklch, var(--vault-signal) 8%, transparent) 1px,
				transparent 1px
			);
		background-size: 32px 32px;
		mask-image: radial-gradient(ellipse 260px 240px at center, black, transparent);
	}
</style>
