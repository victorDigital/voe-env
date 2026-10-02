<script lang="ts">
	import type { EnvItem } from './types.ts';
	import DataTableFolderButton from './data-table-folder-button.svelte';
	import DataTableKeyCell from './data-table-key-cell.svelte';
	import DataTableValueCell from './data-table-value-cell.svelte';
	import DataTableActions from './data-table-actions.svelte';
	import ArrowUp from 'remixicon-svelte/icons/arrow-up-line';
	import ArrowDown from 'remixicon-svelte/icons/arrow-down-line';

	let {
		data,
		currentPath,
		navigateTo,
		onDelete,
		onRequestUnlock,
		showAllValues,
		isUnlocking,
		readOnly = false
	}: {
		data: EnvItem[];
		currentPath: string;
		navigateTo: (path: string) => void;
		onDelete: (name: string) => void;
		onRequestUnlock: () => void;
		showAllValues: boolean;
		isUnlocking: boolean;
		readOnly?: boolean;
	} = $props();

	let ascending = $state(true);
	const sortedItems = $derived(
		[...data].sort((a, b) => {
			if (a.type !== b.type) return a.type === 'folder' ? -1 : 1;
			return a.name.localeCompare(b.name, undefined, { numeric: true }) * (ascending ? 1 : -1);
		})
	);
</script>

<table class="w-full table-fixed text-left text-sm">
	<caption class="sr-only">Environment variables in {currentPath || 'your vault'}</caption>
	<colgroup>
		<col class="w-[43%] sm:w-[38%]" />
		<col />
		<col class="w-9 sm:w-11" />
	</colgroup>
	<thead class="border-b border-border text-xs text-muted-foreground">
		<tr>
			<th
				scope="col"
				aria-sort={ascending ? 'ascending' : 'descending'}
				class="py-3 pr-3 font-normal"
			>
				<button
					type="button"
					onclick={() => (ascending = !ascending)}
					class="inline-flex items-center gap-2 hover:text-foreground"
					aria-label="Sort by name {ascending ? 'descending' : 'ascending'}"
				>
					Name
					{#if ascending}<ArrowUp class="size-3" />{:else}<ArrowDown class="size-3" />{/if}
				</button>
			</th>
			<th scope="col" class="py-3 font-normal">Value</th>
			<th scope="col" class="py-3"><span class="sr-only">Actions</span></th>
		</tr>
	</thead>
	<tbody>
		{#each sortedItems as item (`${item.type}:${item.name}`)}
			<tr class="group border-b border-border transition-colors hover:bg-muted/35">
				<td class="py-4 pr-3 align-top sm:align-middle">
					{#if item.type === 'folder'}
						<DataTableFolderButton
							name={item.name}
							onNavigate={() => navigateTo(currentPath ? `${currentPath}:${item.name}` : item.name)}
							isShared={item.isShared}
							sharedBy={item.sharedBy}
							permission={item.permission}
						/>
					{:else}
						<DataTableKeyCell
							name={item.name}
							isDecrypted={item.value !== undefined}
							{isUnlocking}
						/>
					{/if}
				</td>
				<td class="py-4 align-middle">
					<DataTableValueCell
						name={item.name}
						type={item.type}
						value={item.value}
						encrypted={item.encrypted}
						isDecrypted={item.value !== undefined}
						{showAllValues}
						{onRequestUnlock}
					/>
				</td>
				<td class="py-3 pl-1 text-right align-middle">
					{#if item.type === 'key' && !readOnly}
						<DataTableActions name={item.name} onDelete={() => onDelete(item.name)} />
					{/if}
				</td>
			</tr>
		{/each}
	</tbody>
</table>
