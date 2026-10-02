<script lang="ts">
	import AuthPage from '#lib/components/AuthPage.svelte';
	import type { PageData } from './$types';
	let { data }: { data: PageData } = $props();
</script>

<AuthPage mode="signup" redirectTo={data.redirectTo} />
