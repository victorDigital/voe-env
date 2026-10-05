<script lang="ts">
	import { page } from '$app/state';
	import * as Dialog from '#lib/components/ui/dialog/index.ts';
	import * as Tabs from '#lib/components/ui/tabs/index.ts';
	import { Button } from '#lib/components/ui/button/index.ts';
	import RiFileCopyLine from 'remixicon-svelte/icons/file-copy-line';
	import RiCheckLine from 'remixicon-svelte/icons/check-line';
	let { open = $bindable(false) }: { open?: boolean } = $props();
	let platform = $state('unix');
	let copied = $state(false);
	let error = $state('');
	const quote = (value: string) => `'${value.replaceAll("'", "'\\''")}'`;
	let command = $derived(
		platform === 'windows'
			? `& ([scriptblock]::Create((irm '${page.url.origin.replaceAll("'", "''")}/install.ps1'))) -BaseUrl '${page.url.origin.replaceAll("'", "''")}'`
			: `curl -fsSL ${quote(page.url.origin + '/install.sh')} | sh -s -- ${quote(page.url.origin)}`
	);
	$effect(() => {
		platform;
		open;
		copied = false;
		error = '';
	});
	async function copy() {
		try {
			await navigator.clipboard.writeText(command);
			copied = true;
		} catch {
			error = 'Select the command to copy it.';
		}
	}
</script>

<Dialog.Root bind:open>
	<Dialog.Content class="gap-6 p-6 sm:max-w-lg">
		<Dialog.Header
			><Dialog.Title>Install CLI</Dialog.Title><Dialog.Description
				>Your secrets, in your terminal.</Dialog.Description
			></Dialog.Header
		>
		<Tabs.Root bind:value={platform}>
			<Tabs.List class="mb-4"
				><Tabs.Trigger value="unix">macOS / Linux</Tabs.Trigger><Tabs.Trigger value="windows"
					>Windows</Tabs.Trigger
				></Tabs.List
			>
			<div class="relative border bg-muted/25 p-4 pr-12">
				<code
					class="block font-mono text-xs leading-6 break-all select-all"
					aria-label="Installation command">{command}</code
				><Button
					class="absolute top-2 right-2"
					variant="ghost"
					size="icon-sm"
					aria-label={copied ? 'Command copied' : 'Copy install command'}
					onclick={copy}
					>{#if copied}<RiCheckLine />{:else}<RiFileCopyLine />{/if}</Button
				>
			</div>
			<p class="mt-3 text-xs text-muted-foreground">
				Run in {platform === 'windows' ? 'PowerShell' : 'your terminal'}.
			</p>
		</Tabs.Root>
		{#if error}<p role="alert" class="text-xs text-destructive">{error}</p>{/if}
		<div class="flex items-center justify-between border-t pt-4 text-xs">
			<span class="text-muted-foreground">Then connect your account</span><code class="font-mono"
				>ve auth</code
			>
		</div>
	</Dialog.Content>
</Dialog.Root>
