<script lang="ts">
	import ActionError from './ActionError.svelte';
	import * as AlertDialog from '#lib/components/ui/alert-dialog/index.ts';
	import { Button } from '#lib/components/ui/button/index.ts';
	let {
		open = $bindable(false),
		title,
		description,
		label = 'Confirm',
		error = $bindable(''),
		busy = false,
		onconfirm
	}: {
		open?: boolean;
		title: string;
		description: string;
		label?: string;
		error?: string;
		busy?: boolean;
		onconfirm: () => void;
	} = $props();
</script>

<AlertDialog.Root bind:open>
	<AlertDialog.Content class="max-w-md p-6">
		<AlertDialog.Header
			><AlertDialog.Title>{title}</AlertDialog.Title><AlertDialog.Description
				>{description}</AlertDialog.Description
			></AlertDialog.Header
		>
		<ActionError bind:error />
		<AlertDialog.Footer class="mt-3"
			><AlertDialog.Cancel disabled={busy}>Cancel</AlertDialog.Cancel><Button
				variant="destructive"
				disabled={busy}
				onclick={onconfirm}>{busy ? 'Working…' : label}</Button
			></AlertDialog.Footer
		>
	</AlertDialog.Content>
</AlertDialog.Root>
