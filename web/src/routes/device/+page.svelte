<script lang="ts">
	import { goto } from '$app/navigation';
	import { authClient } from '$lib/auth-client';
	import * as Alert from '$lib/components/ui/alert/index.js';
	import { Button } from '$lib/components/ui/button';
	import * as Item from '$lib/components/ui/item/index.js';
	import * as Avatar from '$lib/components/ui/avatar/index.js';

	import IconAlertCircle from 'virtual:icons/lucide/alert-circle';

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
				error = approveError.error_description || 'Authorization failed';
			} else {
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
	<title>Authorization</title>
</svelte:head>

<div class="flex h-screen w-full flex-1 items-center justify-center p-4">
	<div class="flex w-full max-w-md flex-col gap-4">
		<h1 class="font-bold">Device Authorization</h1>

		{#if showError || error}
			<Alert.Root variant="destructive">
				<IconAlertCircle />
				<Alert.Title>Authorization Error</Alert.Title>
				<Alert.Description>
					<p>Details: {error}</p>
				</Alert.Description>
			</Alert.Root>
		{/if}

		{#if userCode}
			<Item.Root variant="outline">
				<Item.Content>
					<Item.Title>Allow Device</Item.Title>
					<Item.Description>
						Authorize the device using the code: <strong>{userCode}</strong>
					</Item.Description>
				</Item.Content>
				<Item.Actions>
					<Button size="sm" onclick={authorizeDevice}>Authorize</Button>
				</Item.Actions>
			</Item.Root>
		{/if}

		{#if data.user}
			<div class="mt-4 flex items-center">
				<p class="text-sm text-muted-foreground">Logged in as</p>
				{#if data.user.image}
					<Avatar.Root class="mx-1 inline-block h-5 w-5 align-middle">
						<Avatar.Image src={data.user.image} alt={data.user.name} />
						<Avatar.Fallback class="text-xs text-muted-foreground">
							{data.user.name?.charAt(0) ?? 'U'}
						</Avatar.Fallback>
					</Avatar.Root>
				{/if}
				<p class="text-sm font-semibold text-muted-foreground">{data.user.email}</p>
			</div>
		{/if}
	</div>
</div>
