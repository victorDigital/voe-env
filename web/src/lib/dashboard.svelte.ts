import { getContext, setContext, type Snippet } from 'svelte';
import { api } from './vault-client';
export type Workspace = { id: string; name: string; role: string };
const key = Symbol('dashboard');
export class Dashboard {
	workspaces = $state<Workspace[]>([]);
	selected = $state('');
	working = $state(false);
	revision = $state(0);
	createOpen = $state(false);
	header = $state<Snippet | null>(null);
	get workspace() {
		return this.workspaces.find((w) => w.id === this.selected);
	}
	constructor(workspaces: Workspace[], selected: string) {
		this.workspaces = workspaces;
		this.selected = workspaces.some((w) => w.id === selected) ? selected : workspaces[0]?.id || '';
	}
	async refresh() {
		this.workspaces = await api<Workspace[]>('/api/workspaces');
		this.revision++;
		if (!this.workspaces.some((w) => w.id === this.selected))
			this.selected = this.workspaces[0]?.id || '';
	}
}
export const provideDashboard = (workspaces: Workspace[], selected: string) =>
	setContext(key, new Dashboard(workspaces, selected));
export const useDashboard = () => getContext<Dashboard>(key);
