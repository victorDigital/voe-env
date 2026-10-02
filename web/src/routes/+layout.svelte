<script lang="ts">
	import './layout.css';
	import favicon from '#lib/assets/favicon.svg';
	import { ModeWatcher } from 'mode-watcher';

	let { children } = $props();
</script>

<svelte:head><link rel="icon" href={favicon} /></svelte:head>
<ModeWatcher />
<a href="#main-content" class="skip-link">Skip to content</a>
{@render children()}

<style>
	.skip-link {
		position: fixed;
		top: 12px;
		left: 12px;
		z-index: 100;
		transform: translateY(-160%);
		background: var(--primary);
		color: var(--primary-foreground);
		padding: 10px 16px;
		font-size: 13px;
	}
	.skip-link:focus {
		transform: translateY(0);
	}
</style>
