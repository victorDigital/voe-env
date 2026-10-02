<script lang="ts">
	import RiSideBarLine from 'remixicon-svelte/icons/side-bar-line';
	import { Button } from '#lib/components/ui/button/index.ts';
	import { cn } from '#lib/utils.ts';
	import { useSidebar } from './context.svelte.ts';
	import type { ComponentProps } from 'svelte';

	let {
		ref = $bindable(null),
		class: className,
		onclick,
		...restProps
	}: ComponentProps<typeof Button> & {
		onclick?: (e: MouseEvent) => void;
	} = $props();

	const sidebar = useSidebar();
</script>

<Button
	bind:ref
	data-sidebar="trigger"
	data-slot="sidebar-trigger"
	variant="ghost"
	size="icon-sm"
	class={cn(className)}
	type="button"
	aria-expanded={sidebar.isMobile ? sidebar.openMobile : sidebar.open}
	onclick={(e) => {
		onclick?.(e);
		sidebar.toggle();
	}}
	{...restProps}
>
	<RiSideBarLine class="cn-rtl-flip" />
	<span class="sr-only">Toggle Sidebar</span>
</Button>
