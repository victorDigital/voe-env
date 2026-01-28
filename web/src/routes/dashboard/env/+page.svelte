<script lang="ts">
	import { enhance } from '$app/forms';
	import { goto } from '$app/navigation';

	let { data, form } = $props();

	let currentPath = $derived(data.path);
	let vaultPassword = $state('');
	let setKey = $state('');
	let setValue = $state('');
	let getKey = $state('');
	let deleteKey = $state('');

	// For displaying get result
	let getResult = $state<string | null>(null);

	// Encrypted envs from server
	let encryptedEnvs = $derived(data.encryptedEnvs || {});
	let decryptedEnvs = $state<Record<string, string>>({});

	let breadcrumbs = $derived(currentPath ? currentPath.split(':') : []);

	// Client-side encryption functions
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

	// Decrypt all envs when password changes
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
				// Skip invalid
			}
		}
		decryptedEnvs = newDecrypted;
	}

	function b64ByteLength(b64: string): number {
		let len = b64.length;
		let padding = 0;
		if (b64.endsWith('==')) padding = 2;
		else if (b64.endsWith('=')) padding = 1;
		return (len * 3) / 4 - padding;
	}

	function estimateLength(encrypted: string): number {
		console.log('Estimating length for:', encrypted);
		if (typeof encrypted !== 'string' || !encrypted) return 0;
		try {
			const combinedLength = b64ByteLength(encrypted);
			const dataLength = combinedLength - 12;
			const plaintextLength = dataLength - 16;
			return Math.max(0, plaintextLength);
		} catch {
			return 0;
		}
	}

	function navigateTo(path: string) {
		goto(`?path=${encodeURIComponent(path)}`);
	}

	function goUp() {
		const parts = currentPath.split(':');
		parts.pop();
		const newPath = parts.join(':');
		navigateTo(newPath);
	}

	const setEnhance = async ({ formData, cancel }: any) => {
		if (!vaultPassword) {
			cancel();
			return;
		}
		const value = formData.get('value') as string;
		const encryptedValue = await encrypt(value, vaultPassword);
		formData.set('encryptedValue', encryptedValue);
		formData.delete('value');

		return async ({ update }: any) => {
			await update();
		};
	};

	const getEnhance = async ({ formData, cancel }: any) => {
		if (!vaultPassword) {
			cancel();
			return;
		}

		return async ({ result, update }: any) => {
			if (result.type === 'success' && result.data?.encryptedValue) {
				try {
					const value = await decrypt(result.data.encryptedValue, vaultPassword);
					getResult = value;
				} catch {
					getResult = 'Error decrypting value';
				}
			} else {
				getResult = null;
			}
			await update();
		};
	};

	function getLockedString(length: number): string {
		return '•'.repeat(Math.min(length, 20));
	}

	function deleteItem(name: string) {
		deleteKey = currentPath ? `${currentPath}:${name}` : name;
		const form = document.getElementById('delete-form') as HTMLFormElement;
		form.requestSubmit();
	}
</script>

<svelte:head>
	<title>Env Vault</title>
</svelte:head>

<div class="container mx-auto p-4">
	<h1 class="mb-4 text-2xl font-bold">Env Vault</h1>

	<!-- Breadcrumbs -->
	<div class="mb-4">
		<button
			class="text-blue-500 hover:underline"
			onclick={() => navigateTo('')}
			disabled={currentPath === ''}
		>
			Root
		</button>
		{#each breadcrumbs as crumb, i}
			<span> / </span>
			<button
				class="text-blue-500 hover:underline"
				onclick={() => navigateTo(breadcrumbs.slice(0, i + 1).join(':'))}
			>
				{crumb}
			</button>
		{/each}
	</div>

	<!-- Current Path -->
	<p class="mb-4">Current Path: {currentPath || 'Root'}</p>

	<!-- Items List -->
	<div class="mb-8">
		<h2 class="mb-2 text-xl font-semibold">Contents</h2>
		{#if data.items.length === 0}
			<p>No items here.</p>
		{:else}
			<ul class="space-y-2">
				{#each data.items as item}
					<li class="flex items-center space-x-2">
						{#if item.type === 'folder'}
							<span>📁</span>
							<button
								class="text-blue-500 hover:underline"
								onclick={() => navigateTo(currentPath ? `${currentPath}:${item.name}` : item.name)}
							>
								{item.name}
							</button>
						{:else}
							<span>🔑</span>
							<span>
								{#if decryptedEnvs[item.name]}
									{item.name}: {decryptedEnvs[item.name]}
								{:else}
									{item.name}: {getLockedString(estimateLength(encryptedEnvs[item.name]))}
								{/if}
							</span>
							<!-- <span
								>{item.name}: {decryptedEnvs[
									currentPath ? `${currentPath}:${item.name}` : item.name
								] || `${estimateLength(encryptedEnvs[item.name])} chars)`}</span
							> -->
							<button
								class="rounded bg-red-500 px-2 py-1 text-sm text-white"
								onclick={() => deleteItem(item.name)}
							>
								Delete
							</button>
						{/if}
					</li>
				{/each}
			</ul>
		{/if}
	</div>

	<!-- Vault Password -->
	<div class="mb-8">
		<h2 class="mb-2 text-xl font-semibold">Vault Password</h2>
		<div class="mb-2">
			<label for="vault-password" class="block">Enter your vault password:</label>
			<input
				id="vault-password"
				type="password"
				bind:value={vaultPassword}
				class="w-full border p-2"
				required
			/>
		</div>
	</div>

	<!-- Set Env Form -->
	<div class="mb-8">
		<h2 class="mb-2 text-xl font-semibold">Set Environment Variable</h2>
		<form method="POST" action="?/set" use:enhance={setEnhance}>
			<input type="hidden" name="path" value={currentPath} />
			<div class="mb-2">
				<label for="set-key" class="block">Key:</label>
				<input
					id="set-key"
					name="key"
					type="text"
					bind:value={setKey}
					class="w-full border p-2"
					required
				/>
			</div>
			<div class="mb-2">
				<label for="set-value" class="block">Value:</label>
				<input
					id="set-value"
					name="value"
					type="text"
					bind:value={setValue}
					class="w-full border p-2"
					required
				/>
			</div>

			<button
				type="submit"
				class="rounded bg-blue-500 px-4 py-2 text-white"
				disabled={!vaultPassword}>Set</button
			>
		</form>
		{#if form?.success === false && form?.action === 'set'}
			<p class="mt-2 text-red-500">{form.error}</p>
		{:else if form?.success === true && form?.action === 'set'}
			<p class="mt-2 text-green-500">Set successfully!</p>
		{/if}
	</div>

	<!-- Get Env Form -->
	<div class="mb-8">
		<h2 class="mb-2 text-xl font-semibold">Get Environment Variable</h2>
		<form method="POST" action="?/get" use:enhance={getEnhance}>
			<div class="mb-2">
				<label for="get-key" class="block">Full Key:</label>
				<input
					id="get-key"
					name="fullKey"
					type="text"
					bind:value={getKey}
					class="w-full border p-2"
					placeholder="e.g., acme:website:dev:API_KEY"
					required
				/>
			</div>

			<button
				type="submit"
				class="rounded bg-green-500 px-4 py-2 text-white"
				disabled={!vaultPassword}>Get</button
			>
		</form>
		{#if getResult !== null}
			<p class="mt-2 text-green-500">Value: {getResult}</p>
		{:else if form?.success === false && form?.action === 'get'}
			<p class="mt-2 text-red-500">{form.error}</p>
		{/if}
	</div>

	<!-- Delete Form (hidden) -->
	<form id="delete-form" method="POST" action="?/delete" use:enhance>
		<input type="hidden" name="fullKey" bind:value={deleteKey} />
	</form>
</div>
