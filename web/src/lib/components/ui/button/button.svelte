<script lang="ts" module>
	import { type VariantProps, tv } from 'tailwind-variants';
	import type { WithChildren, WithoutChildren } from 'bits-ui';
	import { cn } from '#lib/utils.ts';
	import type { HTMLAnchorAttributes, HTMLButtonAttributes } from 'svelte/elements';
	import type { Hotkey, HotkeyAction } from '#lib/hotkeys/types.ts';

	export const buttonVariants = tv({
		base: "relative overflow-hidden data-[loading=true]:[&_svg]:opacity-0 focus-visible:border-ring focus-visible:ring-ring/50 aria-invalid:ring-destructive/20 dark:aria-invalid:ring-destructive/40 aria-invalid:border-destructive dark:aria-invalid:border-destructive/50 rounded-none border border-transparent bg-clip-padding text-xs font-medium focus-visible:ring-1 aria-invalid:ring-1 active:not-aria-[haspopup]:translate-y-px [&_svg:not([class*='size-'])]:size-4 group/button inline-flex shrink-0 items-center justify-center whitespace-nowrap transition-all outline-none select-none disabled:pointer-events-none disabled:opacity-50 [&_svg]:pointer-events-none [&_svg]:shrink-0",
		variants: {
			variant: {
				default: 'bg-primary text-primary-foreground hover:bg-primary/80',
				outline:
					'border-border bg-background hover:bg-muted hover:text-foreground dark:bg-input/30 dark:border-input dark:hover:bg-input/50 aria-expanded:bg-muted aria-expanded:text-foreground',
				secondary:
					'bg-secondary text-secondary-foreground hover:bg-[color-mix(in_oklch,var(--secondary),var(--foreground)_5%)] aria-expanded:bg-secondary aria-expanded:text-secondary-foreground',
				ghost:
					'hover:bg-muted hover:text-foreground dark:hover:bg-muted/50 aria-expanded:bg-muted aria-expanded:text-foreground',
				destructive:
					'bg-destructive/10 hover:bg-destructive/20 focus-visible:ring-destructive/20 dark:focus-visible:ring-destructive/40 dark:bg-destructive/20 text-destructive focus-visible:border-destructive/40 dark:hover:bg-destructive/30',
				link: 'text-primary underline-offset-4 hover:underline'
			},
			size: {
				default:
					'h-8 gap-1.5 px-2.5 has-data-[icon=inline-end]:pr-2 has-data-[icon=inline-start]:pl-2',
				xs: "h-6 gap-1 rounded-none px-2 text-xs has-data-[icon=inline-end]:pr-1.5 has-data-[icon=inline-start]:pl-1.5 [&_svg:not([class*='size-'])]:size-3",
				sm: "h-7 gap-1 rounded-none px-2.5 has-data-[icon=inline-end]:pr-1.5 has-data-[icon=inline-start]:pl-1.5 [&_svg:not([class*='size-'])]:size-3.5",
				lg: 'h-9 gap-1.5 px-2.5 has-data-[icon=inline-end]:pr-2 has-data-[icon=inline-start]:pl-2',
				icon: 'size-8',
				'icon-xs': "size-6 rounded-none [&_svg:not([class*='size-'])]:size-3",
				'icon-sm': 'size-7 rounded-none',
				'icon-lg': 'size-9'
			}
		},
		defaultVariants: {
			variant: 'default',
			size: 'default'
		}
	});

	export type ButtonVariant = VariantProps<typeof buttonVariants>['variant'];
	export type ButtonSize = VariantProps<typeof buttonVariants>['size'];

	const kbdVariants = tv({
		variants: {
			buttonVariant: {
				default: 'border-primary-foreground/20 bg-primary text-primary-foreground',
				destructive: 'border-destructive/20 bg-destructive/10 text-destructive',
				outline: 'bg-background/50 text-muted-foreground',
				secondary: 'bg-background/50 text-muted-foreground',
				ghost: 'bg-background/50 text-muted-foreground',
				link: 'bg-background/50 text-muted-foreground'
			}
		},
		defaultVariants: { buttonVariant: 'default' }
	});

	export type ButtonClickEvent = MouseEvent & { currentTarget: EventTarget & HTMLElement };
	export type ButtonPropsWithoutHTML = WithChildren<{
		ref?: HTMLElement | null;
		variant?: ButtonVariant;
		size?: ButtonSize;
		loading?: boolean;
		onClickPromise?: (event: ButtonClickEvent) => Promise<void>;
		hotKey?: Hotkey & { handler?: HotkeyAction['handler'] };
		hotKeyComponentId?: string;
		hotKeyHandlerExplicitlyDefined?: boolean;
		showHotKey?: boolean;
	}>;
	export type ButtonProps = ButtonPropsWithoutHTML &
		WithoutChildren<HTMLButtonAttributes> &
		WithoutChildren<HTMLAnchorAttributes>;
</script>

<script lang="ts">
	import { onNavigate } from '$app/navigation';
	import { Debounced } from 'runed';
	import RiLoader4Line from 'remixicon-svelte/icons/loader-4-line';
	import Kbd from '#lib/hotkeys/Kbd.svelte';
	import { getHotkeyManager, useHotkeys } from '#lib/hotkeys/manager.svelte.ts';
	import { ariaKeys, formatKeys } from '#lib/hotkeys/utils.ts';
	let {
		ref = $bindable(null),
		variant = 'default',
		size = 'default',
		href = undefined,
		type = 'button',
		loading = $bindable(false),
		disabled = false,
		tabindex = 0,
		onclick,
		onClickPromise,
		hotKey,
		hotKeyComponentId = 'button',
		hotKeyHandlerExplicitlyDefined = false,
		showHotKey = !size.startsWith('icon'),
		class: className,
		title,
		children,
		...rest
	}: ButtonProps = $props();
	const manager = getHotkeyManager();
	const debouncedLoading = new Debounced(() => loading, 300);
	let unavailable = $derived(disabled || loading);
	let shortcutTitle = $derived(
		hotKey
			? `${title || hotKey.description} (${formatKeys(hotKey.keys, manager?.mac ?? false)})`
			: title
	);
	useHotkeys(
		() => hotKeyComponentId,
		() =>
			hotKey
				? [
						{
							...hotKey,
							id: hotKey.keys,
							enabled: () => !unavailable,
							element: () => ref,
							handler: () => {
								if (unavailable) return;
								if (hotKeyHandlerExplicitlyDefined) hotKey?.handler?.();
								else ref?.click();
							}
						}
					]
				: []
	);
	onNavigate(() => {
		loading = false;
	});
</script>

<svelte:element
	this={href ? 'a' : 'button'}
	{...rest}
	data-slot={rest['data-slot'] ?? 'button'}
	data-loading={debouncedLoading.current}
	aria-busy={loading || rest['aria-busy']}
	title={shortcutTitle}
	aria-keyshortcuts={hotKey ? ariaKeys(hotKey.keys, manager?.mac ?? false) : undefined}
	type={href ? undefined : type}
	href={href && !unavailable ? href : undefined}
	disabled={href ? undefined : unavailable}
	aria-disabled={href ? unavailable : rest['aria-disabled']}
	role={href && unavailable ? 'link' : rest.role}
	tabindex={href && unavailable ? -1 : tabindex}
	class={cn(buttonVariants({ variant, size }), className)}
	bind:this={ref}
	onclick={async (event: ButtonClickEvent) => {
		if (unavailable) {
			event.preventDefault();
			return;
		}
		onclick?.(
			event as MouseEvent & { currentTarget: EventTarget & HTMLButtonElement & HTMLAnchorElement }
		);
		if (event.defaultPrevented) return;
		if (
			href &&
			rest.target !== '_blank' &&
			!event.metaKey &&
			!event.ctrlKey &&
			!event.shiftKey &&
			!event.altKey &&
			event.button === 0
		)
			loading = true;
		if (onClickPromise) {
			loading = true;
			try {
				await onClickPromise(event);
			} finally {
				loading = false;
			}
		}
	}}
>
	{#if debouncedLoading.current}
		<div
			class="pointer-events-none absolute inset-0 flex items-center justify-center bg-inherit"
			aria-hidden="true"
		>
			<RiLoader4Line class="size-4 animate-spin opacity-100!" />
		</div>
		<span class="sr-only">Loading</span>
	{/if}
	{@render children?.()}
	{#if hotKey && showHotKey}
		<Kbd
			ariaHidden
			hideOnTouch
			keys={hotKey.keys}
			class={kbdVariants({ buttonVariant: variant })}
		/>
	{/if}
</svelte:element>
