<script lang="ts">
	import { Button } from '$lib/components/ui/button/index.js';
	import { Input } from '$lib/components/ui/input/index.js';
	import * as Dialog from '$lib/components/ui/dialog/index.js';
	import * as Select from '$lib/components/ui/select/index.js';
	import { Label } from '$lib/components/ui/label/index.js';
	import { encryptWithPublicKey } from '$lib/crypto';

	let { open = $bindable(false), folderPath, vaultPassword }: { open: boolean; folderPath: string; vaultPassword: string } = $props();

	let recipientEmail = $state('');
	let permission = $state<'read' | 'readwrite'>('read');
	let isSubmitting = $state(false);
	let error = $state('');
	let success = $state('');

	const permissions = [
		{ value: 'read', label: 'Read Only', description: 'Can view and decrypt values' },
		{ value: 'readwrite', label: 'Read & Write', description: 'Can view, modify, and delete values' }
	];

	async function handleSubmit() {
		error = '';
		success = '';

		if (!recipientEmail) {
			error = 'Please enter an email address';
			return;
		}

		if (!vaultPassword) {
			error = 'Vault must be unlocked to share';
			return;
		}

		isSubmitting = true;

		try {
			// First, get the recipient's public key
			const keyResponse = await fetch(`/api/keys?email=${encodeURIComponent(recipientEmail)}`);
			const keyResult = await keyResponse.json();

			if (!keyResponse.ok) {
				error = keyResult.error || 'Failed to get recipient public key';
				isSubmitting = false;
				return;
			}

			// Encrypt the vault password with recipient's public key
			const encryptedVaultPassword = await encryptWithPublicKey(vaultPassword, keyResult.publicKey);

			// Create the share with encrypted vault password
			const response = await fetch('/api/shares', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({
					folderPath,
					recipientEmail,
					permission,
					encryptedVaultPassword
				})
			});

			const result = await response.json();

			if (!response.ok) {
				error = result.error || 'Failed to share folder';
			} else {
				success = result.message;
				recipientEmail = '';
				setTimeout(() => {
					open = false;
					success = '';
				}, 2000);
			}
		} catch (err: any) {
			error = err.message || 'Failed to share folder';
		} finally {
			isSubmitting = false;
		}
	}
</script>

<Dialog.Root bind:open>
	<Dialog.Content class="sm:max-w-[425px]">
		<Dialog.Header>
			<Dialog.Title>Share Folder</Dialog.Title>
			<Dialog.Description>
				Share "{folderPath}" with another user. They will receive access to view and decrypt all values in this folder.
			</Dialog.Description>
		</Dialog.Header>

		<form onsubmit={handleSubmit} class="grid gap-4 py-4">
			<div class="grid gap-2">
				<Label for="email">Recipient Email</Label>
				<Input
					id="email"
					type="email"
					placeholder="colleague@example.com"
					bind:value={recipientEmail}
					disabled={isSubmitting}
				/>
			</div>

			<div class="grid gap-2">
				<Label for="permission">Permission</Label>
				<Select.Root type="single" bind:value={permission} disabled={isSubmitting}>
					<Select.Trigger class="w-full">
						{permissions.find((p) => p.value === permission)?.label}
					</Select.Trigger>
					<Select.Content>
						{#each permissions as perm}
							<Select.Item value={perm.value}>
								<div class="flex flex-col">
									<span>{perm.label}</span>
									<span class="text-xs text-muted-foreground">{perm.description}</span>
								</div>
							</Select.Item>
						{/each}
					</Select.Content>
				</Select.Root>
			</div>

			{#if error}
				<p class="text-sm text-red-500">{error}</p>
			{/if}

			{#if success}
				<p class="text-sm text-green-500">{success}</p>
			{/if}
		</form>

	<Dialog.Footer>
		<Button variant="outline" onclick={() => (open = false)} disabled={isSubmitting}>Cancel</Button>
		<Button disabled={isSubmitting || !recipientEmail} onclick={handleSubmit}>
			{#if isSubmitting}
				Sharing...
			{:else}
				Share Folder
			{/if}
		</Button>
	</Dialog.Footer>
	</Dialog.Content>
</Dialog.Root>
