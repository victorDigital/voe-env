<script lang="ts">
	import * as Dialog from '#lib/components/ui/dialog/index.ts';
	import { getHotkeyManager } from './manager.svelte.ts';
	import type { HotkeyAction } from './types.ts';
	import Kbd from './Kbd.svelte';
	const manager = getHotkeyManager()!;
	let groups = $derived.by(() => {
		const result = new Map<string, HotkeyAction[]>();
		const seen = new Set<string>();
		manager.helpOpen;
		for (const action of manager.activeHotkeys) {
			const element = action.element?.();
			if (action.element && !element?.getClientRects().length) continue;
			const identity = `${action.keys}:${action.description}`;
			if (seen.has(identity)) continue;
			seen.add(identity);
			const category = action.category || 'General';
			const actions = result.get(category) || [];
			actions.push(action);
			result.set(category, actions);
		}
		return result;
	});
</script>

<Dialog.Root bind:open={manager.helpOpen}>
	<Dialog.Content class="max-h-[calc(100dvh-2rem)] overflow-y-auto p-6 sm:max-w-md">
		<Dialog.Header>
			<Dialog.Title>Keyboard shortcuts</Dialog.Title>
			<Dialog.Description class="sr-only">Available actions on this page.</Dialog.Description>
		</Dialog.Header>
		{#each [...groups] as [category, actions] (category)}
			<section>
				<h3 class="mb-2 text-xs font-medium text-muted-foreground">{category}</h3>
				<div class="divide-y">
					{#each actions as action (`${action.keys}:${action.description}`)}
						<div class="flex items-center justify-between gap-4 py-2 text-xs">
							<span>{action.description}</span><Kbd keys={action.keys} />
						</div>
					{/each}
				</div>
			</section>
		{/each}
		<div class="flex items-center justify-between border-t pt-3 text-xs text-muted-foreground">
			<span>Show shortcuts</span><Kbd keys="?" />
		</div>
	</Dialog.Content>
</Dialog.Root>
