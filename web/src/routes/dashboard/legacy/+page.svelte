<script lang="ts">
	import { goto } from '$app/navigation';
	import { Button } from '#lib/components/ui/button/index.ts';
	import { Input } from '#lib/components/ui/input/index.ts';
	import { getStoredPrivateKey, decryptWithPrivateKey } from '#lib/crypto.ts';
	import { bytes, decode } from '#lib/vault-crypto.ts';
	import DataTable from '../env/data-table.svelte';
	import type { PageData } from './$types';
	let { data }: { data: PageData } = $props();
	let password = $state('');
	let values = $state<Record<string, string>>({});
	let busy = $state(false);
	let error = $state('');
	let show = $state(false);
	let active = $state('');
	$effect(() => {
		const key = data.ownerId + ':' + data.path;
		if (active !== key) {
			active = key;
			password = '';
			values = {};
			show = false;
			error = '';
		}
	});
	const table = $derived(
		data.items.map((item) => ({
			...item,
			value: values[item.name],
			encrypted: data.encryptedEnvs[item.name]
		}))
	);
	async function unlock() {
		busy = true;
		error = '';
		const source = data;
		try {
			let keyPassword = password;
			if (!keyPassword && source.encryptedVaultPassword) {
				const privateKey = getStoredPrivateKey();
				if (privateKey)
					keyPassword = await decryptWithPrivateKey(source.encryptedVaultPassword, privateKey);
			}
			if (!keyPassword)
				throw new Error(
					'Enter the original password, or open this archive in the browser that received the share.'
				);
			const material = await crypto.subtle.importKey('raw', bytes(keyPassword), 'PBKDF2', false, [
				'deriveKey'
			]);
			const key = await crypto.subtle.deriveKey(
				{ name: 'PBKDF2', salt: bytes('fixedsalt'), iterations: 100000, hash: 'SHA-256' },
				material,
				{ name: 'AES-GCM', length: 256 },
				false,
				['decrypt']
			);
			const decrypted: Record<string, string> = {};
			for (const [name, value] of Object.entries(source.encryptedEnvs)) {
				const raw = decode(value);
				decrypted[name] = new TextDecoder().decode(
					await crypto.subtle.decrypt({ name: 'AES-GCM', iv: raw.slice(0, 12) }, key, raw.slice(12))
				);
			}
			if (data === source) {
				values = decrypted;
				password = '';
				show = true;
			}
		} catch {
			error =
				'Could not unlock this archive. Use its original password or the original sharing browser.';
		} finally {
			busy = false;
		}
	}
	function navigate(path: string) {
		return goto(
			`/dashboard/legacy?owner=${encodeURIComponent(data.ownerId)}&path=${encodeURIComponent(path)}`
		);
	}
</script>

<svelte:head><title>Legacy archive · VOE</title></svelte:head>
<div class="p-6 sm:p-8">
	<Button variant="ghost" href="/dashboard/env">← Workspaces</Button>
	<h1 class="mt-6 text-2xl font-semibold">Legacy archive</h1>
	<p class="mt-3 text-sm text-muted-foreground">
		Read-only access to old vaults and shares. New secrets belong in workspaces. Keep your original
		browser keys until migration is verified.
	</p>
	<Button class="mt-4" variant="outline" href="/dashboard/migrate">Migrate your vaults</Button>
	<div class="mt-6 flex flex-wrap items-center gap-3">
		<Button variant="outline" href="/dashboard/legacy">Your archive</Button
		>{#if data.path && data.path !== data.shareRoot}<Button
				variant="ghost"
				onclick={() => navigate(data.path.split(':').slice(0, -1).join(':'))}
				>← Parent folder</Button
			>{/if}<code class="text-sm">{data.path || '/'}</code>
	</div>
	{#if Object.keys(data.encryptedEnvs).length}<form
			class="mt-5 flex flex-wrap gap-2"
			onsubmit={(e) => {
				e.preventDefault();
				unlock();
			}}
		>
			<Input
				class="max-w-xs"
				aria-label="Legacy vault password"
				type="password"
				autocomplete="off"
				placeholder="Original vault password"
				bind:value={password}
			/><Button type="submit" disabled={busy}>Unlock archive</Button><Button
				variant="outline"
				onclick={() => {
					values = {};
					show = false;
					password = '';
				}}>Lock</Button
			>
		</form>{/if}
	{#if error}<p role="alert" class="mt-3 text-sm text-destructive">{error}</p>{/if}
	<div class="mt-6">
		<DataTable
			data={table}
			currentPath={data.path}
			navigateTo={navigate}
			onDelete={() => {}}
			onRequestUnlock={unlock}
			showAllValues={show}
			isUnlocking={busy}
			readOnly
		/>
	</div>
	{#if !data.items.length}<p class="mt-5 text-sm text-muted-foreground">
			No archived secrets here.
		</p>{/if}
	{#if data.incoming.length}<section class="mt-8">
			<h2 class="font-medium">Shared with you</h2>
			{#each data.incoming as share}<a
					class="mt-3 block text-sm underline underline-offset-4"
					href={`/dashboard/legacy?owner=${encodeURIComponent(share.ownerId)}&path=${encodeURIComponent(share.path)}`}
					>{share.path} · {share.owner}</a
				>{/each}
		</section>{/if}
</div>
