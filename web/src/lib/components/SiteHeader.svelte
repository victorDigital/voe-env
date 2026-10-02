<script lang="ts">
	import { Button } from '#lib/components/ui/button/index.ts';
	let { signedIn = false, auth = false }: { signedIn?: boolean; auth?: boolean } = $props();
</script>

<header class="site-header">
	<a href="/" class="wordmark" aria-label="VOE home">voe<span>.</span></a>
	<nav aria-label="Main navigation">
		{#if auth}
			<a href="/#install" class="nav-link">Install CLI</a>
		{:else}
			{#if signedIn}
				<Button href="/dashboard" size="sm" class="h-9 px-4">Open vault</Button>
			{:else}
				<a href="/login" class="nav-link">Log in</a>
				<Button href="/signup" size="sm" class="h-9 px-4">Sign up</Button>
			{/if}
		{/if}
	</nav>
</header>

<style>
	.site-header {
		display: flex;
		height: 76px;
		align-items: center;
		justify-content: space-between;
		border-bottom: 1px solid var(--border);
	}
	.wordmark {
		font-size: 25px;
		font-weight: 650;
		line-height: 1;
		letter-spacing: -0.075em;
	}
	.wordmark span {
		color: color-mix(in oklch, var(--primary) 75%, var(--foreground));
	}
	nav {
		display: flex;
		gap: 24px;
		align-items: center;
	}
	.nav-link {
		font-size: 13px;
		color: var(--muted-foreground);
	}
	.nav-link:hover {
		color: var(--foreground);
	}
	@media (max-width: 640px) {
		.site-header {
			height: 72px;
		}
		nav {
			gap: 20px;
		}
	}
</style>
