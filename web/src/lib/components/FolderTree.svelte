<script lang="ts">
	import { untrack } from 'svelte';
	import type { Folder } from '#lib/vault-format.ts';
	import RiArrowRightSLine from 'remixicon-svelte/icons/arrow-right-s-line';
	import RiFolderLine from 'remixicon-svelte/icons/folder-line';
	type Row = { folder: Folder; depth: number; guides: number[]; last: boolean };

	let {
		folders,
		selected,
		onnavigate
	}: { folders: Folder[]; selected: string; onnavigate: (id: string) => void } = $props();
	let expanded = $state(new Set<string>());
	let byId = $derived(new Map(folders.map((folder) => [folder.id, folder])));
	let children = $derived.by(() => {
		const result = new Map<string | null, Folder[]>();
		for (const folder of folders) {
			const siblings = result.get(folder.parentId) || [];
			siblings.push(folder);
			result.set(folder.parentId, siblings);
		}
		for (const siblings of result.values()) siblings.sort((a, b) => a.name.localeCompare(b.name));
		return result;
	});
	let rows = $derived.by(() => {
		const result: Row[] = [];
		const roots = children.get(null) || [];
		const pending: Row[] = roots
			.map((folder, index) => ({
				folder,
				depth: 0,
				guides: [],
				last: index === roots.length - 1
			}))
			.reverse();
		while (pending.length) {
			const row = pending.pop()!;
			result.push(row);
			if (expanded.has(row.folder.id)) {
				const siblings = children.get(row.folder.id) || [];
				for (let i = siblings.length - 1; i >= 0; i--)
					pending.push({
						folder: siblings[i],
						depth: row.depth + 1,
						guides: row.depth && !row.last ? [...row.guides, row.depth - 1] : row.guides,
						last: i === siblings.length - 1
					});
			}
		}
		return result;
	});
	$effect(() => {
		let folder = byId.get(selected);
		const next = new Set(untrack(() => expanded));
		while (folder) {
			next.add(folder.id);
			folder = folder.parentId ? byId.get(folder.parentId) : undefined;
		}
		expanded = next;
	});
	function toggle(id: string) {
		const next = new Set(expanded);
		if (next.has(id)) next.delete(id);
		else next.add(id);
		expanded = next;
	}
</script>

<nav aria-label="Folders">
	<ul>
		{#each rows as { folder, depth, guides, last } (folder.id)}
			{@const name = folder.parentId ? folder.name : 'Vault'}
			<li>
				<div
					class="relative flex h-11 min-w-0 items-center text-xs hover:bg-muted/50 md:h-9"
					class:bg-muted={selected === folder.id}
					style:padding-left={`${depth * 24}px`}
				>
					<div
						aria-hidden="true"
						class="pointer-events-none absolute inset-0 text-muted-foreground/30"
					>
						{#each guides as level}
							<span
								class="absolute inset-y-0 border-l border-current"
								style:left={`${16 + level * 24}px`}
							></span>
						{/each}
						{#if depth}
							<span
								class="absolute top-0 border-l border-current"
								style:left={`${16 + (depth - 1) * 24}px`}
								style:height={last ? 'calc(50% - 4px)' : '100%'}
							></span>
							<span
								class="absolute top-[calc(50%-4px)] origin-top-left rotate-45 border-t border-current"
								style:left={`${16 + (depth - 1) * 24}px`}
								style:width={`${4 * Math.SQRT2}px`}
							></span>
							<span
								class="absolute top-1/2 border-t border-current"
								style:left={`${20 + (depth - 1) * 24}px`}
								style:width={children.has(folder.id) ? '9px' : '31px'}
							></span>
						{/if}
						{#if children.has(folder.id) && expanded.has(folder.id)}
							<span
								class="absolute top-[calc(50%+11px)] bottom-0 border-l border-current"
								style:left={`${16 + depth * 24}px`}
							></span>
						{/if}
					</div>
					{#if children.has(folder.id)}
						<button
							type="button"
							class="flex h-full w-8 shrink-0 items-center justify-center text-muted-foreground outline-none hover:text-foreground focus-visible:ring-1 focus-visible:ring-ring focus-visible:ring-inset"
							aria-label={`${expanded.has(folder.id) ? 'Collapse' : 'Expand'} ${name}`}
							aria-expanded={expanded.has(folder.id)}
							onclick={() => toggle(folder.id)}
						>
							<RiArrowRightSLine
								class={expanded.has(folder.id) ? 'size-3.5 rotate-90' : 'size-3.5'}
							/>
						</button>
					{:else}
						<span class="w-8 shrink-0"></span>
					{/if}
					<button
						type="button"
						class="flex h-full min-w-0 flex-1 items-center gap-2 pr-3 text-left outline-none focus-visible:ring-1 focus-visible:ring-ring focus-visible:ring-inset"
						class:font-medium={selected === folder.id}
						aria-current={selected === folder.id ? 'location' : undefined}
						title={name}
						onclick={() => onnavigate(folder.id)}
					>
						<RiFolderLine class="size-3.5 shrink-0 text-muted-foreground" />
						<span class="truncate">{name}</span>
					</button>
				</div>
			</li>
		{/each}
	</ul>
</nav>
