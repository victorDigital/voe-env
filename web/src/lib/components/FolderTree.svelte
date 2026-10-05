<script lang="ts">
	import { untrack } from 'svelte';
	import type { Folder } from '#lib/vault-format.ts';
	import RiArrowRightSLine from 'remixicon-svelte/icons/arrow-right-s-line';
	import RiFolderLine from 'remixicon-svelte/icons/folder-line';
	type Row = { folder: Folder; depth: number };

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
		const pending: Row[] = roots.map((folder) => ({ folder, depth: 0 })).reverse();
		while (pending.length) {
			const row = pending.pop()!;
			result.push(row);
			if (expanded.has(row.folder.id)) {
				const siblings = children.get(row.folder.id) || [];
				for (let i = siblings.length - 1; i >= 0; i--)
					pending.push({
						folder: siblings[i],
						depth: row.depth + 1
					});
			}
		}
		return result;
	});
	let branches = $derived.by(() => {
		const indices = new Map(rows.map((row, index) => [row.folder.id, index]));
		const result = new Map<number, number[]>();
		rows.forEach((row, index) => {
			const parent = row.folder.parentId ? indices.get(row.folder.parentId) : undefined;
			if (parent === undefined) return;
			const siblings = result.get(parent) || [];
			siblings.push(index);
			result.set(parent, siblings);
		});
		return result;
	});
	let lineWidth = $derived(Math.max(0, ...rows.map((row) => row.depth)) * 24 + 64);
	function connectorPath(height: number) {
		const result: string[] = [];
		for (const [parent, siblings] of branches) {
			const x = 16.5 + rows[parent].depth * 24;
			const last = siblings[siblings.length - 1];
			const y = (last + 0.5) * height + 0.5;
			const end = (index: number) => x + (children.has(rows[index].folder.id) ? 13 : 35);
			result.push(`M${x} ${(parent + 0.5) * height + 11.5} V${y - 4} L${x + 4} ${y} H${end(last)}`);
			for (const index of siblings.slice(0, -1)) {
				const y = (index + 0.5) * height + 0.5;
				result.push(`M${x} ${y - 4} L${x + 4} ${y} H${end(index)}`);
			}
		}
		return result.join(' ');
	}
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

{#snippet connectors(height: number, className: string)}
	<svg
		aria-hidden="true"
		focusable="false"
		class={`pointer-events-none absolute top-0 left-0 h-full ${className}`}
		style:color="color-mix(in srgb, var(--muted-foreground) 30%, var(--background))"
		width={lineWidth}
		height={rows.length * height}
		viewBox={`0 0 ${lineWidth} ${rows.length * height}`}
		preserveAspectRatio="none"
	>
		<path
			d={connectorPath(height)}
			fill="none"
			stroke="currentColor"
			stroke-width="1"
			stroke-linecap="butt"
			stroke-linejoin="miter"
		/>
	</svg>
{/snippet}

<nav aria-label="Folders" class="relative">
	<ul>
		{#each rows as { folder, depth } (folder.id)}
			{@const name = folder.parentId ? folder.name : 'Vault'}
			<li>
				<div
					class="flex h-11 min-w-0 items-center text-xs hover:bg-muted/50 md:h-9"
					class:bg-muted={selected === folder.id}
					style:padding-left={`${depth * 24}px`}
				>
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
	{#if rows.length}
		{@render connectors(44, 'md:hidden')}
		{@render connectors(36, 'hidden md:block')}
	{/if}
</nav>
