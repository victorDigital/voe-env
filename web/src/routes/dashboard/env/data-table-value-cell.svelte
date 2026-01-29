<script lang="ts">
	import { Button } from '$lib/components/ui/button/index.js';
	import Copy from '@lucide/svelte/icons/copy';
	import Eye from '@lucide/svelte/icons/eye';
	import EyeOff from '@lucide/svelte/icons/eye-off';

	let {
		type,
		name,
		value,
		encrypted,
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

	let isHovered = $state(false);
	let localShowValue = $state(false);
	let showValue = $derived(isDecrypted && showAllValues ? true : localShowValue);

	function b64ByteLength(b64: string): number {
		let len = b64.length;
		let padding = 0;
		if (b64.endsWith('==')) padding = 2;
		else if (b64.endsWith('=')) padding = 1;
		return (len * 3) / 4 - padding;
	}

	function estimateLength(encrypted: string): number {
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

	function getLockedString(length: number): string {
		return '•'.repeat(Math.min(length, 60));
	}

	async function handleCopy() {
		if (!value) return;
		try {
			await navigator.clipboard.writeText(value);
			console.log('Copied to clipboard');
		} catch (err) {
			console.error('Failed to copy:', err);
		}
	}

	function handleToggleVisibility() {
		if (!isDecrypted && encrypted) {
			// Need password - bubble up event to page
			onRequestUnlock?.();
			return;
		}
		localShowValue = !localShowValue;
	}

	function handleMouseEnter() {
		isHovered = true;
	}

	function handleMouseLeave() {
		isHovered = false;
	}

	function truncate(str: string, maxLength = 60): string {
		if (str.length <= maxLength) return str;
		return str.slice(0, maxLength - 1) + '…';
	}
</script>

<div
	class="flex items-center justify-between gap-2"
	role="group"
	onmouseenter={handleMouseEnter}
	onmouseleave={handleMouseLeave}
>
	<div class="min-w-0 flex-1 overflow-hidden">
		{#if type === 'folder'}
			<span class="text-muted-foreground">—</span>
		{:else}
			<span
				class="block truncate font-mono text-sm text-muted-foreground"
				title={isDecrypted && showValue ? value : undefined}
			>
				{#if isDecrypted && showValue}
					{truncate(value || '')}
				{:else if isDecrypted && !showValue}
					{getLockedString(value?.length || 0)}
				{:else}
					{getLockedString(estimateLength(encrypted || ''))}
				{/if}
			</span>
		{/if}
	</div>

	{#if type !== 'folder' && isHovered}
		<div class="flex shrink-0 items-center gap-1">
			{#if isDecrypted}
				<Button
					variant="ghost"
					size="icon"
					class="h-6 w-6"
					onclick={handleToggleVisibility}
					title={showValue ? 'Hide value' : 'Show value'}
				>
					{#if showValue}
						<EyeOff class="h-3 w-3" />
					{:else}
						<Eye class="h-3 w-3" />
					{/if}
				</Button>
			{:else}
				<Button
					variant="ghost"
					size="icon"
					class="h-6 w-6"
					onclick={handleToggleVisibility}
					title="Unlock to view"
				>
					<Eye class="h-3 w-3" />
				</Button>
			{/if}

			{#if isDecrypted && value}
				<Button
					variant="ghost"
					size="icon"
					class="h-6 w-6"
					onclick={handleCopy}
					title="Copy to clipboard"
				>
					<Copy class="h-3 w-3" />
				</Button>
			{/if}
		</div>
	{/if}
</div>
