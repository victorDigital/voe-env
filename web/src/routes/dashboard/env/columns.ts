import type { ColumnDef } from '@tanstack/table-core';
import { renderComponent } from '$lib/components/ui/data-table/index.js';
import DataTableFolderButton from './data-table-folder-button.svelte';
import DataTableKeyCell from './data-table-key-cell.svelte';
import DataTableValueCell from './data-table-value-cell.svelte';
import DataTableActions from './data-table-actions.svelte';

export type EnvItem = {
	name: string;
	type: 'folder' | 'key';
	value?: string;
	encrypted?: string;
	isShared?: boolean;
	sharedBy?: { email: string; name: string };
	permission?: 'read' | 'readwrite';
};

export function getColumns(
	currentPath: string,
	onNavigate: (path: string) => void,
	onDelete: (name: string) => void,
	onRequestUnlock: () => void,
	showAllValues: boolean,
	isUnlocking: boolean
): ColumnDef<EnvItem>[] {
	return [
		{
			accessorKey: 'name',
			header: 'Name',
			size: 100,
			meta: {
				className: 'whitespace-nowrap'
			},
			cell: ({ row }) => {
				const item = row.original;
				if (item.type === 'folder') {
					return renderComponent(DataTableFolderButton, {
						name: item.name,
						onNavigate: () => onNavigate(currentPath ? `${currentPath}:${item.name}` : item.name),
						isShared: item.isShared,
						sharedBy: item.sharedBy,
						permission: item.permission
					});
				}
				return renderComponent(DataTableKeyCell, {
					name: item.name,
					isDecrypted: !!item.value,
					isUnlocking
				});
			}
		},
		{
			accessorKey: 'value',
			header: 'Value',
			size: 1000,
			cell: ({ row }) => {
				const item = row.original;
				return renderComponent(DataTableValueCell, {
					name: item.name,
					type: item.type,
					value: item.value,
					encrypted: item.encrypted,
					isDecrypted: !!item.value,
					showAllValues,
					onRequestUnlock
				});
			}
		},
		{
			id: 'actions',
			header: '',
			size: 48,
			minSize: 48,
			maxSize: 48,
			meta: {
				className: 'text-right'
			},
			cell: ({ row }) => {
				const item = row.original;
				if (item.type === 'folder') {
					return '';
				}
				return renderComponent(DataTableActions, {
					onDelete: () => onDelete(item.name)
				});
			}
		}
	];
}
