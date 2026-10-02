<script lang="ts">
	import { Button } from '#lib/components/ui/button/index.ts';
	import Copy from 'remixicon-svelte/icons/file-copy-line';
	import Check from 'remixicon-svelte/icons/check-line';
	import Eye from 'remixicon-svelte/icons/eye-line';
	import EyeOff from 'remixicon-svelte/icons/eye-off-line';

	let {
		type,
		name,
		value,
		isDecrypted,
		showAllValues,
		onRequestUnlock
	}: {
		type: 'folder' | 'key';
		name: string;
		value?: string;
		encrypted?: string;
		isDecrypted: boolean;
		showAllValues: boolean;
		onRequestUnlock?: () => void;
	} = $props();

	let localShowValue = $state<boolean | null>(null);
	let copied = $state(false);
	let copyError = $state('');
	let showValue = $derived(isDecrypted && (localShowValue ?? showAllValues));

	$effect(() => {
		showAllValues;
		isDecrypted;
		localShowValue = null;
	});

	async function handleCopy() {
		if (value === undefined) return;
		copyError = '';
		try {
			await navigator.clipboard.writeText(value);
			copied = true;
			setTimeout(() => (copied = false), 2000);
		} catch {
			copyError = 'Could not copy. Reveal the value to select it.';
		}
	}

	function handleToggleVisibility() {
		if (!isDecrypted) {
			onRequestUnlock?.();
			return;
		}
		localShowValue = !showValue;
	}
</script>

{#if type === 'folder'}
	<span class="text-xs text-muted-foreground/60">—</span>
{:else}
	<div
		class="flex min-w-0 gap-1 {showValue
			? 'flex-col items-start sm:flex-row sm:items-center'
			: 'items-center justify-between'}"
		role="group"
		aria-label="Value for {name}"
	>
		<span
			class="min-w-0 font-mono text-xs {showValue
				? 'break-all whitespace-pre-wrap text-foreground sm:flex-1'
				: 'truncate text-muted-foreground'}"
		>
			{showValue ? value || '(empty)' : '••••••••'}
		</span>
		<div class="flex shrink-0 items-center">
			<Button
				variant="ghost"
				size="icon"
				class="size-8 text-muted-foreground"
				onclick={handleToggleVisibility}
				aria-label={isDecrypted ? `${showValue ? 'Hide' : 'Reveal'} ${name}` : `Unlock ${name}`}
				title={isDecrypted ? (showValue ? 'Hide value' : 'Reveal value') : 'Unlock to view'}
			>
				{#if showValue}<EyeOff class="size-3.5" />{:else}<Eye class="size-3.5" />{/if}
			</Button>
			{#if isDecrypted}
				<Button
					variant="ghost"
					size="icon"
					class="size-8 text-muted-foreground"
					onclick={handleCopy}
					aria-label={copied ? `Copied ${name}` : `Copy ${name}`}
					title={copied ? 'Copied' : 'Copy value'}
				>
					{#if copied}<Check class="size-3.5 text-primary" />{:else}<Copy class="size-3.5" />{/if}
				</Button>
			{/if}
		</div>
	</div>
	<span class="sr-only" role="status">{copied ? 'Value copied.' : ''}</span>
	{#if copyError}<p role="alert" class="mt-1 text-[11px] text-destructive">{copyError}</p>{/if}
{/if}
