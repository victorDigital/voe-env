<script lang="ts">
	import { Button } from '#lib/components/ui/button/index.ts';
	import * as DropdownMenu from '#lib/components/ui/dropdown-menu/index.ts';
	import MoreHorizontal from 'remixicon-svelte/icons/more-line';
	import Trash from 'remixicon-svelte/icons/delete-bin-line';

	let { name, onDelete }: { name: string; onDelete: () => void } = $props();
</script>

<DropdownMenu.Root>
	<DropdownMenu.Trigger>
		{#snippet child({ props })}
			<Button
				variant="ghost"
				size="icon"
				class="size-8 text-muted-foreground"
				aria-label="Actions for {name}"
				{...props}
			>
				<MoreHorizontal class="size-4" />
			</Button>
		{/snippet}
	</DropdownMenu.Trigger>
	<DropdownMenu.Content align="end">
		<DropdownMenu.Item onclick={onDelete} class="text-destructive">
			<Trash class="mr-2 size-3.5" />
			Delete variable
		</DropdownMenu.Item>
	</DropdownMenu.Content>
</DropdownMenu.Root>
