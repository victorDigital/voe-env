<script lang="ts">
	import { enhance } from '$app/forms';
	import { goto } from '$app/navigation';
	import { onMount, tick } from 'svelte';
	import { Button } from '#lib/components/ui/button/index.ts';
	import { Input } from '#lib/components/ui/input/index.ts';
	import * as Dialog from '#lib/components/ui/dialog/index.ts';
	import { Label } from '#lib/components/ui/label/index.ts';
	import type { PageData } from './$types';
	import DataTable from './data-table.svelte';
	import type { EnvItem } from './types.ts';
	import Lock from 'remixicon-svelte/icons/lock-line';
	import LockOpen from 'remixicon-svelte/icons/lock-unlock-line';
	import Users from 'remixicon-svelte/icons/group-line';
	import Share2 from 'remixicon-svelte/icons/share-line';
	import ShareDialog from './ShareDialog.svelte';
	import { initializeKeys, getStoredPrivateKey, decryptWithPrivateKey } from '#lib/crypto.ts';

	let { data, form }: { data: PageData; form: any } = $props();

	let currentPath = $derived(data.path);
	let shareInfo = $derived(data.shareInfo || { isShared: false }) as {
		isShared: boolean;
		sharedBy?: { email: string; name: string };
		permission?: 'read' | 'readwrite';
		encryptedVaultPassword?: string;
	};
	let vaultPassword = $state('');
	let tempPassword = $state('');
	let deleteKey = $state('');
	let showPasswordPrompt = $state(false);
	let unlockError = $state('');
	let isUnlocking = $state(false);
	let showAllValues = $state(false);
	let pendingShowAll = $state(false);
	let showShareDialog = $state(false);
	let keysInitialized = $state(false);
	let pendingShare = $state(false);
	let skipAutoUnlock = $state(false);
	let pendingDelete = $state('');
	let showDeleteDialog = $state(false);
	let deleting = $state(false);
	let clientError = $state('');
	let passwordInput = $state<HTMLInputElement | null>(null);
	let activePath = $state<string | undefined>();
	let vaultGeneration = 0;

	let encryptedEnvs = $derived(data.encryptedEnvs || {});
	let decryptedEnvs = $state<Record<string, string>>({});
	let breadcrumbs = $derived(currentPath ? currentPath.split(':') : []);

	onMount(async () => {
		try {
			const { publicKey, isNew } = await initializeKeys();
			if (isNew) {
				await fetch('/api/keys', {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ publicKey })
				});
			}
			keysInitialized = true;
		} catch (err) {
			console.error('Failed to initialize encryption keys:', err);
			clientError = 'Sharing is unavailable in this browser. Your vault can still be unlocked.';
		}
	});

	$effect(() => {
		if (activePath === currentPath) return;
		activePath = currentPath;
		vaultGeneration += 1;
		vaultPassword = '';
		decryptedEnvs = {};
		showAllValues = false;
		showShareDialog = false;
		showDeleteDialog = false;
		pendingDelete = '';
		deleteKey = '';
		isUnlocking = false;
		skipAutoUnlock = false;
		cancelUnlock();
	});

	$effect(() => {
		if (
			shareInfo.isShared &&
			shareInfo.encryptedVaultPassword &&
			!vaultPassword &&
			keysInitialized &&
			!skipAutoUnlock
		) {
			decryptSharedPassword();
		}
	});

	async function decryptSharedPassword() {
		const privateKey = getStoredPrivateKey();
		if (!privateKey || !shareInfo.encryptedVaultPassword) return;

		const generation = vaultGeneration;
		const path = currentPath;
		const encryptedPassword = shareInfo.encryptedVaultPassword;
		try {
			const decryptedPassword = await decryptWithPrivateKey(encryptedPassword, privateKey);
			if (
				generation === vaultGeneration &&
				currentPath === path &&
				!skipAutoUnlock &&
				shareInfo.encryptedVaultPassword === encryptedPassword
			) {
				vaultPassword = decryptedPassword;
			}
		} catch (err) {
			console.error('Failed to decrypt shared vault password:', err);
		}
	}

	async function deriveKey(password: string): Promise<CryptoKey> {
		const keyMaterial = await crypto.subtle.importKey(
			'raw',
			new TextEncoder().encode(password),
			'PBKDF2',
			false,
			['deriveKey']
		);
		return crypto.subtle.deriveKey(
			{
				name: 'PBKDF2',
				salt: new TextEncoder().encode('fixedsalt'),
				iterations: 100000,
				hash: 'SHA-256'
			},
			keyMaterial,
			{ name: 'AES-GCM', length: 256 },
			false,
			['encrypt', 'decrypt']
		);
	}

	async function decrypt(encrypted: string, password: string): Promise<string> {
		const key = await deriveKey(password);
		const combined = new Uint8Array(
			atob(encrypted)
				.split('')
				.map((c) => c.charCodeAt(0))
		);
		const iv = combined.slice(0, 12);
		const data = combined.slice(12);
		const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, data);
		return new TextDecoder().decode(decrypted);
	}

	async function tryUnlock() {
		if (!tempPassword) {
			unlockError = 'Please enter a password';
			return;
		}

		isUnlocking = true;
		unlockError = '';
		const generation = vaultGeneration;
		const source = encryptedEnvs;
		const password = tempPassword;

		try {
			const firstKey = Object.keys(source)[0];
			if (firstKey) {
				await decrypt(source[firstKey], password);
			}

			if (generation !== vaultGeneration || source !== encryptedEnvs) return;
			vaultPassword = password;
			await decryptAllEnvs();
			if (generation !== vaultGeneration || source !== encryptedEnvs) return;
			showPasswordPrompt = false;
			tempPassword = '';
			if (pendingShowAll) {
				showAllValues = true;
				pendingShowAll = false;
			}
			if (pendingShare) {
				pendingShare = false;
				showShareDialog = true;
			}
		} catch (err) {
			if (generation !== vaultGeneration) return;
			unlockError = 'Invalid password. Please try again.';
			console.error('Unlock error:', err);
		} finally {
			if (generation === vaultGeneration) isUnlocking = false;
		}
	}

	function cancelUnlock() {
		showPasswordPrompt = false;
		tempPassword = '';
		unlockError = '';
		pendingShowAll = false;
		pendingShare = false;
	}

	async function handleRequestUnlock() {
		showPasswordPrompt = true;
		unlockError = '';
		await tick();
		passwordInput?.focus();
	}

	function handleShowAll() {
		if (Object.keys(encryptedEnvs).length > 0 && !vaultPassword) {
			pendingShowAll = true;
			handleRequestUnlock();
		} else {
			showAllValues = !showAllValues;
		}
	}

	$effect(() => {
		if (vaultPassword && Object.keys(encryptedEnvs).length > 0) {
			decryptAllEnvs();
		} else {
			decryptedEnvs = {};
		}
	});

	async function decryptAllEnvs() {
		const generation = vaultGeneration;
		const password = vaultPassword;
		const source = encryptedEnvs;
		const newDecrypted: Record<string, string> = {};
		for (const [key, enc] of Object.entries(source)) {
			try {
				newDecrypted[key] = await decrypt(enc as string, password);
			} catch {}
		}
		if (generation === vaultGeneration && vaultPassword === password && encryptedEnvs === source) {
			decryptedEnvs = newDecrypted;
		}
	}

	function navigateTo(path: string) {
		goto(`?path=${encodeURIComponent(path)}`);
	}

	function requestDelete(name: string) {
		pendingDelete = name;
		showDeleteDialog = true;
	}

	async function deleteItem() {
		deleteKey = currentPath ? `${currentPath}:${pendingDelete}` : pendingDelete;
		await tick();
		const deleteForm = document.getElementById('delete-form') as HTMLFormElement;
		deleteForm.requestSubmit();
	}

	function handleShare() {
		if (!vaultPassword) {
			pendingShare = true;
			handleRequestUnlock();
		} else {
			showShareDialog = true;
		}
	}

	function lockVault() {
		vaultGeneration += 1;
		skipAutoUnlock = true;
		vaultPassword = '';
		decryptedEnvs = {};
		showAllValues = false;
		isUnlocking = false;
		cancelUnlock();
	}

	const tableData = $derived<EnvItem[]>(
		data.items.map((item: any) => ({
			name: item.name,
			type: item.type,
			value: decryptedEnvs[item.name],
			encrypted: encryptedEnvs[item.name],
			isShared: item.isShared,
			sharedBy: item.sharedBy,
			permission: item.permission
		}))
	);
</script>

<svelte:head>
	<title>Vault — VOE</title>
	<meta
		name="description"
		content="Your encrypted environment variables, organized and ready to use."
	/>
</svelte:head>

<div class="flex min-w-0 flex-1 flex-col">
	<section aria-label="Environment variables" class="min-w-0 px-4 py-6 sm:px-6 sm:py-8">
		{#if clientError || form?.error}
			<p role="alert" class="mb-6 border-l-2 border-destructive py-1 pl-3 text-sm text-destructive">
				{clientError || form.error}
			</p>
		{/if}

		<div class="flex flex-wrap items-center justify-between gap-3 border-b border-border pb-4">
			<nav aria-label="Vault folders" class="flex min-w-0 flex-wrap items-center gap-2 text-sm">
				<button
					type="button"
					onclick={() => navigateTo('')}
					aria-current={!currentPath ? 'page' : undefined}
					class="transition-colors hover:text-foreground {currentPath
						? 'text-muted-foreground'
						: 'font-medium'}">All variables</button
				>
				{#each breadcrumbs as crumb, i}
					<span aria-hidden="true" class="text-muted-foreground/50">/</span>
					<button
						type="button"
						onclick={() => navigateTo(breadcrumbs.slice(0, i + 1).join(':'))}
						aria-current={i === breadcrumbs.length - 1 ? 'page' : undefined}
						class="max-w-52 truncate transition-colors hover:text-foreground {i ===
						breadcrumbs.length - 1
							? 'font-medium'
							: 'text-muted-foreground'}">{crumb}</button
					>
				{/each}
			</nav>
			<div class="flex items-center gap-3">
				{#if Object.keys(encryptedEnvs).length > 0}
					<p class="flex items-center gap-1.5 text-xs text-muted-foreground" role="status">
						{#if vaultPassword}<LockOpen class="size-3.5" aria-hidden="true" />{:else}<Lock
								class="size-3.5"
								aria-hidden="true"
							/>{/if}
						{vaultPassword ? 'Unlocked' : 'Locked'}
					</p>
				{/if}
				{#if currentPath && !shareInfo.isShared}
					<Button
						variant="ghost"
						size="sm"
						onclick={handleShare}
						disabled={!keysInitialized}
						class="text-muted-foreground"
						><Share2 class="size-3.5" aria-hidden="true" />Share folder</Button
					>
				{/if}
			</div>
		</div>

		{#if shareInfo.isShared}
			<div class="flex flex-wrap items-center gap-x-3 gap-y-1 pt-4 text-xs text-muted-foreground">
				<Users class="size-3.5" />
				<span>Shared by {shareInfo.sharedBy?.name || shareInfo.sharedBy?.email}</span>
				<span class="text-muted-foreground/50" aria-hidden="true">·</span>
				<span>{shareInfo.permission === 'readwrite' ? 'Can edit' : 'View only'}</span>
			</div>
		{/if}

		{#if showPasswordPrompt}
			<section aria-labelledby="unlock-heading" class="mt-6 border border-border p-5 sm:p-6">
				<div class="mb-5 flex items-start gap-3">
					<Lock class="mt-0.5 size-4 text-muted-foreground" />
					<div>
						<h2 id="unlock-heading" class="text-sm font-medium">Unlock this folder</h2>
						<p class="mt-1 text-xs leading-relaxed text-muted-foreground">
							Enter the vault password set with ve init.
						</p>
					</div>
				</div>
				<form
					onsubmit={(event) => {
						event.preventDefault();
						tryUnlock();
					}}
					class="max-w-lg"
				>
					<Label for="vault-password" class="sr-only">Vault password</Label>
					<div class="flex flex-wrap gap-2">
						<Input
							id="vault-password"
							type="password"
							autocomplete="off"
							placeholder="Vault password"
							bind:value={tempPassword}
							bind:ref={passwordInput}
							disabled={isUnlocking}
							aria-invalid={!!unlockError}
							aria-describedby={unlockError ? 'unlock-error' : undefined}
							class="min-w-0 flex-1 basis-48"
						/>
						<Button type="submit" disabled={isUnlocking || !tempPassword}
							>{isUnlocking ? 'Unlocking…' : 'Unlock'}</Button
						>
						<Button
							variant="ghost"
							onclick={cancelUnlock}
							disabled={isUnlocking}
							class="text-muted-foreground">Cancel</Button
						>
					</div>
					{#if unlockError}<p id="unlock-error" role="alert" class="mt-3 text-xs text-destructive">
							{unlockError}
						</p>{/if}
				</form>
			</section>
		{/if}

		{#if tableData.length > 0}
			<div class="mt-6 mb-3 flex items-center justify-between gap-3">
				<p class="text-xs text-muted-foreground">
					{tableData.length} item{tableData.length !== 1 ? 's' : ''}
				</p>
				{#if Object.keys(encryptedEnvs).length > 0}
					<div class="flex items-center gap-1">
						{#if vaultPassword}<Button
								variant="ghost"
								size="sm"
								onclick={lockVault}
								class="text-xs text-muted-foreground">Lock</Button
							>{/if}
						<Button
							variant="ghost"
							size="sm"
							onclick={handleShowAll}
							class="text-xs text-muted-foreground"
							>{showAllValues ? 'Hide values' : 'Reveal values'}</Button
						>
					</div>
				{/if}
			</div>
			<DataTable
				data={tableData}
				{currentPath}
				{navigateTo}
				onDelete={requestDelete}
				onRequestUnlock={handleRequestUnlock}
				{showAllValues}
				{isUnlocking}
				readOnly={shareInfo.isShared && shareInfo.permission === 'read'}
			/>
		{:else}
			<div class="flex flex-col items-start py-12">
				<p class="text-lg font-medium tracking-tight">
					{currentPath ? 'No variables in this folder' : 'No variables'}
				</p>
				<p class="mt-2 max-w-sm text-sm leading-relaxed text-muted-foreground">
					Upload a .env file from your project directory:
				</p>
				<div class="mt-4">
					<code class="border border-border px-3 py-1.5 text-xs text-muted-foreground"
						>ve init &amp;&amp; ve push</code
					>
				</div>
			</div>
		{/if}
	</section>

	<form
		id="delete-form"
		method="POST"
		action={`?path=${encodeURIComponent(currentPath)}&/delete`}
		use:enhance={() => {
			deleting = true;
			return async ({ update }) => {
				await update();
				deleting = false;
				showDeleteDialog = false;
			};
		}}
	>
		<input type="hidden" name="fullKey" bind:value={deleteKey} />
		<input type="hidden" name="path" value={currentPath} />
	</form>

	<Dialog.Root bind:open={showDeleteDialog}>
		<Dialog.Content class="sm:max-w-sm">
			<Dialog.Header>
				<Dialog.Title>Delete variable?</Dialog.Title>
				<Dialog.Description
					><span class="font-mono break-all text-foreground">{pendingDelete}</span> will be removed from
					this vault. Your local .env file will stay as it is.</Dialog.Description
				>
			</Dialog.Header>
			<Dialog.Footer class="mt-3">
				<Button variant="outline" onclick={() => (showDeleteDialog = false)} disabled={deleting}
					>Cancel</Button
				>
				<Button variant="destructive" onclick={deleteItem} disabled={deleting}
					>{deleting ? 'Deleting…' : 'Delete variable'}</Button
				>
			</Dialog.Footer>
		</Dialog.Content>
	</Dialog.Root>
	<ShareDialog bind:open={showShareDialog} folderPath={currentPath} {vaultPassword} />
</div>
