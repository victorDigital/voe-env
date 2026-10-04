<script lang="ts">
	import { onMount } from 'svelte';
	import { Button } from '#lib/components/ui/button/index.ts';
	import { Input } from '#lib/components/ui/input/index.ts';
	import VaultAccess from '#lib/components/VaultAccess.svelte';
	import {
		api,
		isUnlocked,
		initializeWorkspace,
		organizationKey,
		decryptWorkspace,
		type Snapshot
	} from '#lib/vault-client.ts';
	import { authClient } from '#lib/auth-client.ts';
	import { randomKey, seal, bytes, decode } from '#lib/vault-crypto.ts';
	import {
		folderPath,
		folderContext,
		secretContext,
		type Folder,
		type Secret
	} from '#lib/vault-format.ts';
	let { data } = $props();
	type Legacy = {
		rows: { id: string; fullKey: string; encryptedValue: string }[];
		shares: { folderPath: string; permission: string; expiresAt: string | null }[];
		digest: string;
		migration: { organizationId: string; status: string } | null;
	};
	let legacy = $state<Legacy | null>(null);
	let passwords = $state<Record<string, string>>({});
	let busy = $state(false);
	let error = $state('');
	let notice = $state('');
	let reviewed = $state(false);
	let destination = $state('');
	let paths = $derived([
		...new Set(legacy?.rows.map((r) => r.fullKey.split(':').slice(0, -1).join(':')) || [])
	]);
	onMount(() => {
		api<Legacy>('/api/legacy')
			.then((r) => {
				legacy = r;
				destination = r.migration?.organizationId || '';
			})
			.catch((e) => (error = e.message));
	});
	async function decrypt(value: string, password: string) {
		const material = await crypto.subtle.importKey('raw', bytes(password), 'PBKDF2', false, [
			'deriveKey'
		]);
		const key = await crypto.subtle.deriveKey(
			{ name: 'PBKDF2', salt: bytes('fixedsalt'), iterations: 100000, hash: 'SHA-256' },
			material,
			{ name: 'AES-GCM', length: 256 },
			false,
			['decrypt']
		);
		const raw = decode(value);
		return new Uint8Array(
			await crypto.subtle.decrypt({ name: 'AES-GCM', iv: raw.slice(0, 12) }, key, raw.slice(12))
		);
	}
	async function migrate() {
		if (!legacy || !reviewed) return;
		busy = true;
		error = '';
		try {
			const plaintext = new Map<string, Uint8Array<ArrayBuffer>>();
			for (const row of legacy.rows) {
				const path = row.fullKey.split(':').slice(0, -1).join(':');
				try {
					plaintext.set(row.fullKey, await decrypt(row.encryptedValue, passwords[path] || ''));
				} catch {
					throw new Error(`Could not unlock ${path || 'root'}. Check its legacy password.`);
				}
			}
			if (!destination) {
				const result = await authClient.organization.create({
					name: 'Personal vault (migrated)',
					slug: `migrated-${crypto.randomUUID()}`
				});
				if (result.error || !result.data)
					throw new Error(result.error?.message || 'Could not create workspace');
				destination = result.data.id;
				await initializeWorkspace(destination);
			}
			await api('/api/legacy', {
				action: 'begin',
				organizationId: destination,
				digest: legacy.digest
			});
			const snapshot = await api<Snapshot>(`/api/workspaces/${destination}`);
			if (snapshot.members.length !== 1 || snapshot.members[0].userId !== data.user.id)
				throw new Error('Use a personal workspace containing only you.');
			if (snapshot.secrets.length)
				throw new Error(
					'Destination already contains data. Use Verify completed migration to check it without overwriting.'
				);
			const orgKey = await organizationKey(snapshot);
			const root = snapshot.folders.find((f) => f.parentId === null)!;
			const folders: Folder[] = [root];
			const secrets: Secret[] = [];
			const keys = new Map<string, Uint8Array<ArrayBuffer>>();
			const rootKey = randomKey();
			root.wrappedKey = await seal(
				orgKey,
				rootKey,
				folderContext(destination, root.id, snapshot.epoch)
			);
			keys.set('', rootKey);
			for (const [path, value] of plaintext) {
				const parts = path.split(':');
				const name = parts.pop()!;
				if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name))
					throw new Error(`Invalid environment key: ${name}`);
				let parent = root;
				let current = '';
				for (const part of parts) {
					if (!part)
						throw new Error(
							'Legacy paths contain an empty segment. Export and repair before migration.'
						);
					current = [current, part].filter(Boolean).join(':');
					let folder = folders.find((f) => f.parentId === parent.id && f.name === part);
					if (!folder) {
						const id = crypto.randomUUID();
						const key = randomKey();
						keys.set(current, key);
						folder = {
							id,
							parentId: parent.id,
							name: part,
							wrappedKey: await seal(orgKey, key, folderContext(destination, id, snapshot.epoch))
						};
						folders.push(folder);
					}
					parent = folder;
				}
				const id = crypto.randomUUID();
				secrets.push({
					id,
					folderId: parent.id,
					name,
					encryptedValue: await seal(
						keys.get(current)!,
						value,
						secretContext(destination, parent.id, id, name, snapshot.epoch)
					)
				});
			}
			orgKey.fill(0);
			keys.forEach((k) => k.fill(0));
			await api(`/api/workspaces/${destination}`, {
				action: 'save',
				revision: snapshot.revision,
				epoch: snapshot.epoch,
				folders,
				secrets
			});
			const saved = await api<Snapshot>(`/api/workspaces/${destination}`);
			const values = await decryptWorkspace(saved);
			for (const secret of saved.secrets) {
				const path = [folderPath(saved.folders, secret.folderId), secret.name]
					.filter(Boolean)
					.join(':');
				if (
					values[secret.id] !==
					new TextDecoder('utf-8', { fatal: true }).decode(plaintext.get(path))
				)
					throw new Error('Migration verification failed');
			}
			plaintext.forEach((v) => v.fill(0));
			await complete(saved.revision);
			passwords = {};
			notice =
				'Migration verified. Your new workspace is ready. Legacy data remains read-only, and existing recipients retain only their old access.';
		} catch (e) {
			error = (e as Error).message;
		} finally {
			busy = false;
		}
	}
	async function complete(revision: number) {
		if (!legacy) return;
		await api('/api/legacy', {
			organizationId: destination,
			digest: legacy.digest,
			verifiedCount: legacy.rows.length,
			revision
		});
		legacy = await api('/api/legacy');
	}
	async function verify() {
		busy = true;
		error = '';
		try {
			if (!legacy) return;
			const saved = await api<Snapshot>(`/api/workspaces/${destination}`);
			const values = await decryptWorkspace(saved);
			for (const row of legacy.rows) {
				const path = row.fullKey.split(':').slice(0, -1).join(':');
				const plain = await decrypt(row.encryptedValue, passwords[path] || '');
				const secret = saved.secrets.find(
					(s) =>
						[folderPath(saved.folders, s.folderId), s.name].filter(Boolean).join(':') ===
						row.fullKey
				);
				if (
					!secret ||
					values[secret.id] !== new TextDecoder('utf-8', { fatal: true }).decode(plain)
				)
					throw new Error('Verification failed; destination differs from legacy data');
				plain.fill(0);
			}
			await complete(saved.revision);
			passwords = {};
			notice = 'Every migrated value verified.';
		} catch (e) {
			error = (e as Error).message;
		} finally {
			busy = false;
		}
	}
</script>

<svelte:head><title>Migrate vaults · VOE</title></svelte:head>
<div class="mx-auto w-full max-w-3xl p-6 sm:p-8">
	<Button variant="ghost" href="/dashboard/env">← Workspaces</Button>
	<h1 class="mt-6 text-2xl font-semibold">Migrate your legacy vaults</h1>
	<p class="mt-3 text-sm text-muted-foreground">
		Unlock each old folder once. We encrypt and verify its values in your personal workspace. Old
		shares stay in the read-only archive; invite people to a separate workspace when you are ready
		to grant organization-wide access.
	</p>
	<VaultAccess userId={data.user.id} />
	{#if legacy && $isUnlocked}<p class="mt-6 text-sm">
			{legacy.rows.length} secrets across {paths.length} folders.
		</p>
		{#if legacy.migration}<p class="mt-3 text-sm">
				Migration {legacy.migration.status}. Destination:
				<code class="select-all">{legacy.migration.organizationId}</code>.
			</p>{/if}
		{#if legacy.shares.length}<div class="mt-4 rounded border p-4">
				<h2 class="font-medium">Existing audiences remain separate</h2>
				{#each legacy.shares as share}<p class="mt-2 text-xs">
						{share.folderPath} · {share.permission} · {share.expiresAt
							? `expires ${new Date(share.expiresAt).toLocaleDateString()}`
							: 'no expiry'}
					</p>{/each}
			</div>{/if}
		<form
			class="mt-6 space-y-4"
			onsubmit={(e) => {
				e.preventDefault();
				migrate();
			}}
		>
			{#each paths as path, i}<label class="block text-sm" for={`legacy-${i}`}
					>{path || 'Root'} — legacy password<Input
						id={`legacy-${i}`}
						class="mt-2"
						type="password"
						autocomplete="off"
						bind:value={passwords[path]}
					/></label
				>{/each}<label class="flex items-start gap-3 text-sm"
				><input type="checkbox" class="mt-1" bind:checked={reviewed} />I have a database backup and
				understand that this copies data into a personal workspace without adding previous
				recipients.</label
			><label class="block text-sm" for="destination"
				>Destination workspace ID (optional, for resuming)<Input
					id="destination"
					class="mt-2"
					bind:value={destination}
				/></label
			>
			<div class="flex flex-wrap gap-2">
				<Button type="submit" disabled={busy || !reviewed || !legacy.rows.length}
					>Migrate and verify</Button
				><Button variant="outline" disabled={busy || !destination || !reviewed} onclick={verify}
					>Verify completed migration</Button
				>
			</div>
		</form>{/if}
	{#if error}<p class="mt-4 text-sm text-destructive" role="alert">{error}</p>{/if}{#if notice}<p
			class="mt-4 text-sm"
			role="status"
		>
			{notice}
		</p>{/if}
</div>
