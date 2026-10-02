<script lang="ts">
	import { Button } from '#lib/components/ui/button/index.ts';
	import { Input } from '#lib/components/ui/input/index.ts';
	import * as Dialog from '#lib/components/ui/dialog/index.ts';
	import { Label } from '#lib/components/ui/label/index.ts';
	import { encryptWithPublicKey } from '#lib/crypto.ts';

	let {
		open = $bindable(false),
		folderPath,
		vaultPassword
	}: { open: boolean; folderPath: string; vaultPassword: string } = $props();

	let recipientEmail = $state('');
	let permission = $state<'read' | 'readwrite'>('read');
	let isSubmitting = $state(false);
	let error = $state('');
	let success = $state('');

	$effect(() => {
		if (!open) {
			error = '';
			success = '';
		}
	});

	async function handleSubmit(event: SubmitEvent) {
		event.preventDefault();
		if (isSubmitting) return;
		error = '';
		success = '';

		if (!recipientEmail.trim()) {
			error = 'Enter an email address.';
			return;
		}
		if (!vaultPassword) {
			error = 'Unlock the folder before sharing it.';
			return;
		}

		isSubmitting = true;
		try {
			const email = recipientEmail.trim();
			const keyResponse = await fetch(`/api/keys?email=${encodeURIComponent(email)}`);
			const keyResult = await keyResponse.json();
			if (!keyResponse.ok) {
				error = keyResult.error || 'Could not find this person’s encryption key.';
				return;
			}

			const encryptedVaultPassword = await encryptWithPublicKey(vaultPassword, keyResult.publicKey);
			const response = await fetch('/api/shares', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({
					folderPath,
					recipientEmail: email,
					permission,
					encryptedVaultPassword
				})
			});
			const result = await response.json();
			if (!response.ok) {
				error = result.error || 'Could not share this folder. Try again.';
			} else {
				success = `Shared with ${email}.`;
				recipientEmail = '';
			}
		} catch (err) {
			error = err instanceof Error ? err.message : 'Could not share this folder. Try again.';
		} finally {
			isSubmitting = false;
		}
	}
</script>

<Dialog.Root bind:open>
	<Dialog.Content class="sm:max-w-md">
		<Dialog.Header>
			<Dialog.Title>Share folder</Dialog.Title>
			<Dialog.Description
				>Give someone access to <span class="font-mono break-all text-foreground">{folderPath}</span
				>. They’ll need a VOE account.</Dialog.Description
			>
		</Dialog.Header>

		<form id="share-folder-form" onsubmit={handleSubmit} class="grid gap-5 py-3">
			<div class="grid gap-2">
				<Label for="share-email" class="text-xs">Email address</Label>
				<Input
					id="share-email"
					type="email"
					autocomplete="email"
					placeholder="you@example.com"
					bind:value={recipientEmail}
					disabled={isSubmitting}
					required
					aria-invalid={!!error}
					aria-describedby={error ? 'share-error' : undefined}
				/>
			</div>
			<fieldset disabled={isSubmitting}>
				<legend class="mb-2 text-xs font-medium">Access</legend>
				<div class="grid grid-cols-2 gap-2">
					<label
						class="cursor-pointer border p-3 transition-colors {permission === 'read'
							? 'border-foreground/50 bg-muted/40'
							: 'border-border'}"
					>
						<span class="flex items-center gap-2 text-sm"
							><input
								type="radio"
								name="permission"
								value="read"
								bind:group={permission}
								class="size-3.5 shrink-0 appearance-none border border-input checked:border-primary checked:bg-primary focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring"
							/>Can view</span
						>
						<span class="mt-1.5 block pl-5 text-xs text-muted-foreground">Read and decrypt</span>
					</label>
					<label
						class="cursor-pointer border p-3 transition-colors {permission === 'readwrite'
							? 'border-foreground/50 bg-muted/40'
							: 'border-border'}"
					>
						<span class="flex items-center gap-2 text-sm"
							><input
								type="radio"
								name="permission"
								value="readwrite"
								bind:group={permission}
								class="size-3.5 shrink-0 appearance-none border border-input checked:border-primary checked:bg-primary focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring"
							/>Can edit</span
						>
						<span class="mt-1.5 block pl-5 text-xs text-muted-foreground"
							>Read, change and delete</span
						>
					</label>
				</div>
			</fieldset>
			{#if error}<p id="share-error" role="alert" class="text-xs text-destructive">{error}</p>{/if}
			{#if success}<p role="status" class="text-sm break-all text-foreground">{success}</p>{/if}
		</form>

		<Dialog.Footer>
			<Button variant="outline" onclick={() => (open = false)} disabled={isSubmitting}
				>{success ? 'Done' : 'Cancel'}</Button
			>
			<Button
				type="submit"
				form="share-folder-form"
				disabled={isSubmitting || !recipientEmail.trim()}
				>{isSubmitting ? 'Sharing…' : 'Share folder'}</Button
			>
		</Dialog.Footer>
	</Dialog.Content>
</Dialog.Root>
