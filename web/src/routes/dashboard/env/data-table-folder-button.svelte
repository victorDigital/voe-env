<script lang="ts">
	import Folder from '@lucide/svelte/icons/folder';
	import { Button } from '$lib/components/ui/button/index.js';

	let { name, onNavigate }: { name: string; onNavigate: () => void } = $props();
</script>

<Button variant="link" size="sm" onclick={onNavigate} class="h-auto gap-1 p-0">
	<Folder class="h-4 w-4 text-muted-foreground" />
	{name}
</Button>
