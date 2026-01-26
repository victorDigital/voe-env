<script lang="ts">
	import { goto } from '$app/navigation';
	import { authClient } from '$lib/auth-client';

	let { data } = $props();

	let loading = $state(false);
	let error = $state('');

	let userCode = $derived(data.userCode);
	let showError = $derived(!userCode);

	async function authorizeDevice() {
		if (!userCode) return;

		loading = true;
		error = '';

		try {
			// Format the code: remove dashes and convert to uppercase
			const formattedCode = userCode.trim().replace(/-/g, '').toUpperCase();
			
			const { data: approveData, error: approveError } = await authClient.device.approve({
				userCode: formattedCode
			});

			if (approveError) {
				error = approveError.message || 'Authorization failed';
			} else {
				alert('Device authorized successfully!');
				goto('/dashboard');
			}
		} catch (err: any) {
			error = err.message || 'Network error';
		} finally {
			loading = false;
		}
	}
</script>

<svelte:head>
	<title>Device Authorization</title>
</svelte:head>

<div class="container mx-auto max-w-md p-4">
	<h1 class="mb-4 text-2xl font-bold">Device Authorization</h1>

	{#if showError || error}
		<div class="mb-4 rounded border border-red-400 bg-red-100 px-4 py-3 text-red-700">
			{error}
		</div>
	{/if}

	{#if userCode}
		<div class="mb-4 rounded border border-blue-400 bg-blue-100 px-4 py-3 text-blue-700">
			<p class="mb-2">A device is requesting access to your account.</p>
			<p class="rounded bg-white p-2 font-mono">Code: {userCode}</p>
		</div>

		<button
			onclick={authorizeDevice}
			disabled={loading}
			class="w-full rounded bg-blue-500 px-4 py-2 font-bold text-white hover:bg-blue-700 disabled:bg-gray-400"
		>
			{#if loading}
				Authorizing...
			{:else}
				Authorize Device
			{/if}
		</button>
	{:else}
		<p>Loading...</p>
	{/if}
</div>
