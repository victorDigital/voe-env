<script lang="ts">
	import { enhance } from '$app/forms';
	import { goto } from '$app/navigation';
	import { Button } from '$lib/components/ui/button/index.js';
	import { Input } from '$lib/components/ui/input/index.js';
	import * as Card from '$lib/components/ui/card/index.js';
	import { Separator } from '$lib/components/ui/separator/index.js';
	import { Alert, AlertDescription, AlertTitle } from '$lib/components/ui/alert/index.js';
	import type { PageData } from './$types';
	import DataTable from './data-table.svelte';
	import { getColumns, type EnvItem } from './columns.js';
	import AlertCircle from '@lucide/svelte/icons/alert-circle';
	import Lock from '@lucide/svelte/icons/lock';
	import Users from '@lucide/svelte/icons/users';
	import Share2 from '@lucide/svelte/icons/share-2';
	import Badge from '$lib/components/ui/badge/badge.svelte';
	import ShareDialog from './ShareDialog.svelte';

	let { data, form }: { data: PageData; form: any } = $props();

	let currentPath = $derived(data.path);
	let shareInfo = $derived(data.shareInfo || { isShared: false });
    let vaultPassword = $state('');
	let tempPassword = $state('');
	let deleteKey = $state('');
	let showPasswordPrompt = $state(false);
	let unlockError = $state('');
	let isUnlocking = $state(false);
	let showAllValues = $state(false);
	let pendingShowAll = $state(false);
	let showShareDialog = $state(false);

	let encryptedEnvs = $derived(data.encryptedEnvs || {});
	let decryptedEnvs = $state<Record<string, string>>({});
	let breadcrumbs = $derived(currentPath ? currentPath.split(':') : []);

	// Auto-unlock shared folders if vault password is provided
	$effect(() => {
		if (shareInfo.isShared && shareInfo.vaultPassword && !vaultPassword) {
			vaultPassword = shareInfo.vaultPassword;
		}
	});

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

	async function encrypt(text: string, password: string): Promise<string> {
		const key = await deriveKey(password);
		const iv = crypto.getRandomValues(new Uint8Array(12));
		const encrypted = await crypto.subtle.encrypt(
			{ name: 'AES-GCM', iv },
			key,
			new TextEncoder().encode(text)
		);
		const combined = new Uint8Array(iv.length + encrypted.byteLength);
		combined.set(iv);
		combined.set(new Uint8Array(encrypted), iv.length);
		return btoa(String.fromCharCode(...combined));
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

		try {
			// Try to decrypt one value to verify password
			const firstKey = Object.keys(encryptedEnvs)[0];
			if (firstKey) {
				await decrypt(encryptedEnvs[firstKey], tempPassword);
			}

			// Password is correct, save it and decrypt all
			vaultPassword = tempPassword;
			await decryptAllEnvs();
			showPasswordPrompt = false;
			tempPassword = '';
			if (pendingShowAll) {
				showAllValues = true;
				pendingShowAll = false;
			}
		} catch (err) {
			unlockError = 'Invalid password. Please try again.';
			console.error('Unlock error:', err);
		} finally {
			isUnlocking = false;
		}
	}

	function cancelUnlock() {
		showPasswordPrompt = false;
		tempPassword = '';
		unlockError = '';
	}

	function handleRequestUnlock() {
		showPasswordPrompt = true;
		unlockError = '';
	}

	function handleShowAll() {
		if (Object.keys(encryptedEnvs).length > 0 && !vaultPassword) {
			// Need to unlock first
			pendingShowAll = true;
			showPasswordPrompt = true;
			unlockError = '';
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
		const newDecrypted: Record<string, string> = {};
		for (const [key, enc] of Object.entries(encryptedEnvs)) {
			try {
				newDecrypted[key] = await decrypt(enc as string, vaultPassword);
			} catch {
				// Skip items that fail to decrypt
			}
		}
		decryptedEnvs = newDecrypted;
	}

	function navigateTo(path: string) {
		goto(`?path=${encodeURIComponent(path)}`);
	}

	function deleteItem(name: string) {
		deleteKey = currentPath ? `${currentPath}:${name}` : name;
		const form = document.getElementById('delete-form') as HTMLFormElement;
		form.requestSubmit();
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

	const columns = $derived(
		getColumns(currentPath, navigateTo, deleteItem, handleRequestUnlock, showAllValues, isUnlocking)
	);
</script>

<svelte:head>
	<title>Env Vault</title>
</svelte:head>

<div class="container mx-auto max-w-5xl p-6">
	<div class="mb-6">
		<div class="flex items-start justify-between">
			<div>
				<h1 class="text-2xl font-semibold tracking-tight">Environment Vault</h1>
				{#if shareInfo.isShared}
					<div class="mt-2 flex items-center gap-2">
						<Badge variant="secondary" class="flex items-center gap-1">
							<Users class="h-3 w-3" />
							Shared by {shareInfo.sharedBy?.name || shareInfo.sharedBy?.email}
						</Badge>
						<Badge variant={shareInfo.permission === 'readwrite' ? 'default' : 'outline'}>
							{shareInfo.permission === 'readwrite' ? 'Read & Write' : 'Read Only'}
						</Badge>
					</div>
				{/if}
			</div>
			{#if currentPath && !shareInfo.isShared}
				<Button variant="outline" size="sm" onclick={() => (showShareDialog = true)} class="flex items-center gap-2">
					<Share2 class="h-4 w-4" />
					Share
				</Button>
			{/if}
		</div>
		<div class="mt-2 flex items-center gap-2 text-sm text-muted-foreground">
			<Button
				variant="ghost"
				size="sm"
				onclick={() => navigateTo('')}
				disabled={currentPath === ''}
			>
				Root
			</Button>
			{#each breadcrumbs as crumb, i}
				<span>/</span>
				<Button
					variant="ghost"
					size="sm"
					onclick={() => navigateTo(breadcrumbs.slice(0, i + 1).join(':'))}
				>
					{crumb}
				</Button>
			{/each}
		</div>
	</div>

	{#if showPasswordPrompt}
		<Card.Root class="mb-6 border-yellow-500/50 bg-yellow-500/10">
			<Card.Header>
				<div class="flex items-center gap-2">
					<Lock class="h-5 w-5 text-yellow-600" />
					<Card.Title class="text-base">Unlock Required</Card.Title>
				</div>
				<Card.Description>
					Enter the vault password to view encrypted values in {currentPath || 'Root'}
				</Card.Description>
			</Card.Header>
			<Card.Content class="space-y-4">
				{#if unlockError}
					<Alert variant="destructive">
						<AlertCircle class="h-4 w-4" />
						<AlertTitle>Error</AlertTitle>
						<AlertDescription>{unlockError}</AlertDescription>
					</Alert>
				{/if}
				<div class="flex gap-2">
					<Input
						type="password"
						placeholder="Enter vault password..."
						bind:value={tempPassword}
						onkeydown={(e) => e.key === 'Enter' && tryUnlock()}
						class="max-w-sm"
					/>
					<Button onclick={tryUnlock} disabled={isUnlocking}>
						{#if isUnlocking}
							Unlocking...
						{:else}
							Unlock
						{/if}
					</Button>
					<Button variant="ghost" onclick={cancelUnlock}>Cancel</Button>
				</div>
			</Card.Content>
		</Card.Root>
	{/if}

	<div class="mb-2 flex items-center justify-between">
		<div class="text-sm text-muted-foreground">
			{tableData.length} item{tableData.length !== 1 ? 's' : ''}
		</div>
		<Button
			variant="outline"
			size="sm"
			onclick={handleShowAll}
		>
			{showAllValues ? 'Hide All' : 'Show All'}
		</Button>
	</div>

	<DataTable data={tableData} {columns} />

	<form id="delete-form" method="POST" action="?/delete" use:enhance>
		<input type="hidden" name="fullKey" bind:value={deleteKey} />
	</form>

	<ShareDialog bind:open={showShareDialog} folderPath={currentPath} vaultPassword={vaultPassword} />
</div>
