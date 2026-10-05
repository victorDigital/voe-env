<script lang="ts">
	import { onMount } from 'svelte';
	import { goto, invalidateAll } from '$app/navigation';
	import { authClient } from '#lib/auth-client.ts';
	import { api, lock } from '#lib/vault-client.ts';
	import { Button } from '#lib/components/ui/button/index.ts';
	import { Input } from '#lib/components/ui/input/index.ts';
	import { Label } from '#lib/components/ui/label/index.ts';
	let { data } = $props();
	let name = $state('');
	let error = $state('');
	let busy = $state(false);
	let ready = $state(false);
	onMount(() => {
		ready = true;
	});
	let signedIn = $state(false);
	let wrongAccount = $derived(
		!!data.user &&
			!!data.invitation &&
			data.user.email.toLowerCase() !== data.invitation.email.toLowerCase()
	);
	async function accept() {
		if (busy || !data.invitation) return;
		busy = true;
		error = '';
		try {
			if (!signedIn && (!data.user || !data.user.emailVerified)) {
				await api('/api/auth/sign-in/invitation', {
					invitationId: data.invitation.id,
					token: data.token,
					name: name.trim() || undefined
				});
				signedIn = true;
			}
			const result = await authClient.organization.acceptInvitation({
				invitationId: data.invitation.id
			});
			if (result.error) throw new Error(result.error.message);
			await goto(`/dashboard/env?workspace=${encodeURIComponent(data.invitation.organizationId)}`, {
				refreshAll: true
			});
		} catch (e) {
			error = (e as Error).message;
		} finally {
			busy = false;
		}
	}
	async function signOut() {
		busy = true;
		error = '';
		try {
			const result = await authClient.signOut();
			if (result.error) throw new Error(result.error.message);
			lock();
			await invalidateAll();
		} catch (e) {
			error = (e as Error).message;
		} finally {
			busy = false;
		}
	}
</script>

<svelte:head><title>Workspace invitation · VOE</title></svelte:head>
<main id="main-content" class="mx-auto w-full max-w-sm px-6 py-24">
	<a class="text-xl font-semibold" href="/">voe.</a>
	{#if data.invitation}
		<h1 class="mt-8 text-2xl font-semibold">Join {data.invitation.organizationName}</h1>
		<p class="mt-3 text-sm text-muted-foreground">Invited as {data.invitation.email}</p>
		{#if wrongAccount}
			<p class="mt-6 text-sm">You’re signed in as {data.user?.email}.</p>
			<Button class="mt-6 w-full" disabled={busy || !ready} onclick={signOut}
				>Sign out to continue</Button
			>
		{:else}
			<form
				class="mt-8 space-y-5"
				onsubmit={(e) => {
					e.preventDefault();
					accept();
				}}
			>
				{#if data.needsName && !signedIn}
					<div class="space-y-2">
						<Label for="invite-name">Your name</Label><Input
							id="invite-name"
							bind:value={name}
							autocomplete="name"
							maxlength={100}
							required
						/>
					</div>
				{/if}
				<Button type="submit" class="w-full" disabled={busy || !ready}
					>{busy ? 'Joining…' : 'Join workspace'}</Button
				>
			</form>
			<p class="mt-4 text-xs text-muted-foreground">
				{data.needsName
					? 'Next, create your passkey.'
					: 'An admin will approve your encryption access.'}
			</p>
		{/if}
	{:else}
		<h1 class="mt-8 text-2xl font-semibold">Invitation unavailable</h1>
		<p class="mt-3 text-sm text-muted-foreground">
			This link has expired or already been used. Ask for a new invitation.
		</p>
		<a class="mt-6 inline-block text-sm underline underline-offset-4" href="/login">Sign in</a>
	{/if}
	{#if error}<p role="alert" class="mt-4 text-sm text-destructive">{error}</p>{/if}
</main>
