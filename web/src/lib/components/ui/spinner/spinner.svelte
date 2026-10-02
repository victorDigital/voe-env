<script lang="ts">
	import RiLoaderLine from 'remixicon-svelte/icons/loader-line';
	import { cn } from '#lib/utils.ts';
	import type { SVGAttributes } from 'svelte/elements';

	let {
		class: className,
		role = 'status',
		name,
		color,
		stroke,
		className: legacyClassName,
		'aria-label': ariaLabel = 'Loading',
		...restProps
	}: SVGAttributes<SVGSVGElement> = $props();
</script>

<RiLoaderLine
	{role}
	{...name != null ? { name } : {}}
	{...color != null ? { color } : {}}
	{...stroke != null ? { stroke } : {}}
	{...legacyClassName != null ? { className: legacyClassName } : {}}
	aria-label={ariaLabel}
	class={cn('size-4 animate-spin', className)}
	{...restProps}
/>
