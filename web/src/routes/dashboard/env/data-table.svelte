<script lang="ts" generics="TData, TValue">
	import {
		type ColumnDef,
		type SortingState,
		getCoreRowModel,
		getSortedRowModel
	} from '@tanstack/table-core';
	import {
		createSvelteTable,
		FlexRender
	} from '$lib/components/ui/data-table/index.js';
	import * as Table from '$lib/components/ui/table/index.js';
	import { Button } from '$lib/components/ui/button/index.js';

	type DataTableProps<TData, TValue> = {
		data: TData[];
		columns: ColumnDef<TData, TValue>[];
	};

	let { data, columns }: DataTableProps<TData, TValue> = $props();

	let sorting = $state<SortingState>([]);

	const table = createSvelteTable({
		get data() {
			return data;
		},
		get columns() {
			return columns;
		},
		state: {
			get sorting() {
				return sorting;
			}
		},
		onSortingChange: (updater) => {
			if (typeof updater === 'function') {
				sorting = updater(sorting);
			} else {
				sorting = updater;
			}
		},
		getCoreRowModel: getCoreRowModel(),
		getSortedRowModel: getSortedRowModel()
	});
</script>

<div class="rounded-md border">
	<Table.Root class="w-full">
		<Table.Header>
			{#each table.getHeaderGroups() as headerGroup (headerGroup.id)}
				<Table.Row>
					{#each headerGroup.headers as header (header.id)}
						{@const meta = header.column.columnDef.meta as { className?: string } | undefined}
						<Table.Head
							class={meta?.className ?? ''}
							style="width: {header.getSize()}px"
						>
							{#if !header.isPlaceholder}
								{#if header.column.id === 'name'}
									<Button
										variant="ghost"
										size="sm"
										onclick={header.column.getToggleSortingHandler()}
										class="h-8 p-0 font-medium"
									>
										<FlexRender
											content={header.column.columnDef.header}
											context={header.getContext()}
										/>
										{#if header.column.getIsSorted() === 'asc'}
											↑
										{:else if header.column.getIsSorted() === 'desc'}
											↓
										{/if}
									</Button>
								{:else}
									<FlexRender
										content={header.column.columnDef.header}
										context={header.getContext()}
									/>
								{/if}
							{/if}
						</Table.Head>
					{/each}
				</Table.Row>
			{/each}
		</Table.Header>
		<Table.Body>
			{#each table.getRowModel().rows as row (row.id)}
				<Table.Row data-state={row.getIsSelected() && 'selected'}>
					{#each row.getVisibleCells() as cell (cell.id)}
						{@const meta = cell.column.columnDef.meta as { className?: string } | undefined}
						<Table.Cell
							class={meta?.className ?? ''}
							style="width: {cell.column.getSize()}px"
						>
							<FlexRender
								content={cell.column.columnDef.cell}
								context={cell.getContext()}
							/>
						</Table.Cell>
					{/each}
				</Table.Row>
			{:else}
				<Table.Row>
					<Table.Cell colspan={columns.length} class="h-24 text-center text-muted-foreground">
						No items found.
					</Table.Cell>
				</Table.Row>
			{/each}
		</Table.Body>
	</Table.Root>
</div>
