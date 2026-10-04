<script lang="ts">
	import { goto } from '$app/navigation';
	import { authClient } from '#lib/auth-client.ts';
	import { Button } from '#lib/components/ui/button/index.ts';
	let { data } = $props();
	let error = $state('');
	let busy = $state(false);
	async function accept() {
		busy = true;
		try {
			const result = await authClient.organization.acceptInvitation({
				invitationId: data.invitation.id
			});
			if (result.error) throw new Error(result.error.message);
			await goto('/dashboard/env', { refreshAll: true });
		} catch (e) {
			error = (e as Error).message;
		} finally {
			busy = false;
		}
	}
</script>

<svelte:head><title>Workspace invitation · VOE</title></svelte:head>
<main class="mx-auto max-w-lg p-8 pt-24">
	<a class="text-xl font-semibold" href="/">voe.</a>
	<h1 class="mt-8 text-2xl font-semibold">Join {data.invitation.organizationName}</h1>
	<p class="mt-4 text-sm text-muted-foreground">
		You are invited as a {data.invitation.role}. Members can access every folder in this workspace.
		After joining, set up your passkey and ask an admin to approve encryption access.
	</p>
	<p class="mt-4 text-sm">Signed in as {data.user.email}</p>
	<Button class="mt-6" disabled={busy} onclick={accept}>Accept invitation</Button>{#if error}<p
			role="alert"
			class="mt-4 text-destructive"
		>
			{error}
		</p>{/if}
</main>
