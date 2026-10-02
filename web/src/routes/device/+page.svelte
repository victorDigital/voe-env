<script lang="ts">
	import { goto } from '$app/navigation';
	import { authClient } from '#lib/auth-client.ts';
	import { Button } from '#lib/components/ui/button/index.ts';
	import { Input } from '#lib/components/ui/input/index.ts';
	import { Label } from '#lib/components/ui/label/index.ts';
	import type { PageData } from './$types';

	let { data }: { data: PageData } = $props();
	let pendingAction = $state<'approve' | 'deny' | null>(null);
	let loading = $derived(pendingAction !== null);
	let error = $state('');
	let approved = $state(false);
	let userCode = $derived(data.userCode);

	async function respondToDevice(approve: boolean) {
		if (!userCode || loading) return false;
		pendingAction = approve ? 'approve' : 'deny';
		error = '';
		try {
			const formattedCode = userCode.trim().replace(/[\s-]/g, '').toUpperCase();
			const verification = await authClient.device({ query: { user_code: formattedCode } });
			if (verification.error) {
				error = verification.error.error_description || 'Could not verify this code. Try again.';
				return false;
			}
			if (verification.data?.status !== 'pending') {
				error = 'This code has already been used. Run ve auth again.';
				return false;
			}
			const result = approve
				? await authClient.device.approve({ userCode: formattedCode })
				: await authClient.device.deny({ userCode: formattedCode });
			if (result.error) {
				if (result.error.status === 401 && approve) {
					await goto(
						`/login?redirectTo=${encodeURIComponent(`/device?user_code=${formattedCode}`)}`
					);
					return false;
				}
				error = result.error.error_description || 'Could not authorize this device. Try again.';
				return false;
			} else if (approve) {
				approved = true;
			}
			return true;
		} catch (err) {
			error = err instanceof Error ? err.message : 'Could not connect. Try again.';
			return false;
		} finally {
			pendingAction = null;
		}
	}

	function authorizeDevice() {
		return respondToDevice(true);
	}

	async function denyDevice() {
		if (await respondToDevice(false)) await goto('/dashboard/env');
	}
</script>

<svelte:head>
	<title>{approved ? 'Device authorized' : 'Authorize CLI'} · VOE</title>
	<meta name="description" content="Securely connect the VOE CLI to your account." />
</svelte:head>

<div class="flex min-h-svh flex-col">
	<header class="border-b border-border">
		<div
			class="mx-auto flex h-16 max-w-[1160px] items-center justify-between px-6 sm:h-20 sm:px-10"
		>
			<a href="/" aria-label="VOE homepage" class="text-[22px] font-semibold tracking-tight"
				>voe<span class="text-primary">.</span></a
			>
			<a
				href="/dashboard/env"
				class="text-xs text-muted-foreground transition-colors hover:text-foreground">Vault</a
			>
		</div>
	</header>

	<main id="main-content" class="flex flex-1 items-center justify-center px-6 py-16 sm:py-24">
		<div class="w-full max-w-[360px]">
			{#if approved}
				<h1 class="text-3xl font-medium tracking-tight">Device authorized</h1>
				<p class="mt-3 text-sm leading-relaxed text-muted-foreground" role="status">
					Return to your terminal.
				</p>
				<Button href="/dashboard/env" class="mt-8 w-full">Open vault</Button>
			{:else if !userCode}
				<h1 class="text-3xl font-medium tracking-tight">Enter device code</h1>
				<p class="mt-3 text-sm leading-relaxed text-muted-foreground">
					Run <code class="text-xs text-foreground">ve auth</code> in your terminal and open the link
					it gives you.
				</p>
				<form action="/device" method="GET" class="mt-8 space-y-4">
					<Label for="user-code">Device code</Label>
					<Input
						id="user-code"
						name="user_code"
						placeholder="ABCD-EFGH"
						autocomplete="off"
						autocapitalize="characters"
						spellcheck={false}
						maxlength={16}
						required
					/>
					<Button type="submit" class="w-full">Continue</Button>
				</form>
			{:else}
				<h1 class="text-3xl font-medium tracking-tight">Authorize CLI</h1>
				<p class="mt-3 text-sm leading-relaxed text-muted-foreground">
					Check that this code matches the one in your terminal before continuing.
				</p>
				<div class="mt-8 border-y border-border py-6 text-center">
					<p class="font-mono text-3xl tracking-[0.12em] break-all">{userCode}</p>
				</div>
				{#if error || data.verificationError}
					<p role="alert" class="mt-4 text-xs leading-relaxed text-destructive">
						{error || data.verificationError}
					</p>
					<a href="/device" class="mt-2 block text-xs underline underline-offset-4"
						>Enter another code</a
					>
				{/if}
				<Button
					onclick={authorizeDevice}
					disabled={loading || !!data.verificationError}
					class="mt-6 w-full"
					>{pendingAction === 'approve' ? 'Authorizing…' : 'Authorize device'}</Button
				>
				<Button
					variant="ghost"
					onclick={denyDevice}
					disabled={loading}
					class="mt-2 w-full text-muted-foreground">Cancel</Button
				>
			{/if}
			{#if data.user}
				<p
					class="mt-8 border-t border-border pt-5 text-center text-xs leading-relaxed text-muted-foreground"
				>
					Signed in as <span class="break-all text-foreground">{data.user.email}</span>
				</p>
			{/if}
		</div>
	</main>
</div>
