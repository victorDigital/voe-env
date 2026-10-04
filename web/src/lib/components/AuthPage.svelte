<script lang="ts">
	import { goto } from '$app/navigation';
	import { authClient } from '#lib/auth-client.ts';
	import { signInAndUnlock } from '#lib/vault-client.ts';
	import { Button } from '#lib/components/ui/button/index.ts';
	import { Input } from '#lib/components/ui/input/index.ts';
	import SiteHeader from './SiteHeader.svelte';
	import SiteFooter from './SiteFooter.svelte';
	let { mode, redirectTo }: { mode: 'login' | 'signup'; redirectTo: string } = $props();
	let email = $state('');
	let name = $state('');
	let busy = $state(false);
	let error = $state('');
	let sent = $state(false);
	async function signin() {
		busy = true;
		error = '';
		try {
			await signInAndUnlock();
			await goto(redirectTo, { refreshAll: true });
		} catch (e) {
			error = (e as Error).message;
		} finally {
			busy = false;
		}
	}
	async function send(event: SubmitEvent) {
		event.preventDefault();
		busy = true;
		error = '';
		try {
			const result = await authClient.signIn.magicLink({
				email: email.trim(),
				name: name.trim() || undefined,
				callbackURL: redirectTo
			});
			if (result.error) throw new Error(result.error.message);
			sent = true;
		} catch (e) {
			error = (e as Error).message;
		} finally {
			busy = false;
		}
	}
</script>

<svelte:head><title>{mode === 'signup' ? 'Create an account' : 'Sign in'} · VOE</title></svelte:head
>
<div class="site-shell flex min-h-svh flex-col">
	<SiteHeader auth />
	<main id="main-content" class="flex flex-1 items-center justify-center py-16">
		<section class="w-full max-w-sm" aria-labelledby="auth-title">
			<h1 id="auth-title" class="text-3xl font-medium tracking-tight">
				{mode === 'signup' ? 'Your secrets. Your keys.' : 'Welcome back'}
			</h1>
			<p class="mt-3 text-sm leading-relaxed text-muted-foreground">
				{mode === 'signup'
					? 'Create your passwordless workspace.'
					: 'Sign in and unlock your vault with your passkey.'}
			</p>
			{#if mode === 'login'}<Button class="mt-8 h-11 w-full" disabled={busy} onclick={signin}
					>Sign in with passkey</Button
				>{/if}
			<form onsubmit={send} class="mt-8 space-y-4">
				{#if mode === 'signup'}<label class="block text-sm" for="name"
						>Name<Input
							id="name"
							class="mt-2"
							bind:value={name}
							autocomplete="name"
							required
						/></label
					>{/if}
				<label class="block text-sm" for="email"
					>Email<Input
						id="email"
						class="mt-2"
						type="email"
						bind:value={email}
						autocomplete="email"
						required
					/></label
				>
				<Button type="submit" variant="outline" class="h-11 w-full" disabled={busy}
					>{mode === 'signup' ? 'Send setup link' : 'Email a sign-in link'}</Button
				>
			</form>
			<p class="mt-4 text-xs leading-relaxed text-muted-foreground">
				Email lets you set up or recover your account. Existing secrets still require an enrolled
				passkey or your offline recovery key.
			</p>
			{#if sent}<p role="status" class="mt-4 text-sm">
					Check your email for a link. It expires in 10 minutes.
				</p>{/if}
			{#if error}<p role="alert" class="mt-4 text-sm text-destructive">{error}</p>{/if}
			<p class="mt-8 text-center text-sm text-muted-foreground">
				<a
					class="underline underline-offset-4"
					href={`${mode === 'login' ? '/signup' : '/login'}?redirectTo=${encodeURIComponent(redirectTo)}`}
					>{mode === 'login' ? 'Create an account' : 'Already have a passkey? Sign in'}</a
				>
			</p>
		</section>
	</main>
	<SiteFooter />
</div>
