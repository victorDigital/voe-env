<script lang="ts">
	import { goto } from '$app/navigation';
	import { authClient } from '#lib/auth-client.ts';
	import { Button } from '#lib/components/ui/button/index.ts';
	import { Input } from '#lib/components/ui/input/index.ts';
	import { Label } from '#lib/components/ui/label/index.ts';
	import SiteHeader from './SiteHeader.svelte';
	import SiteFooter from './SiteFooter.svelte';
	import Eye from 'remixicon-svelte/icons/eye-line';
	import EyeOff from 'remixicon-svelte/icons/eye-off-line';
	import LoaderCircle from 'remixicon-svelte/icons/loader-4-line';

	let { mode, redirectTo }: { mode: 'login' | 'signup'; redirectTo: string } = $props();
	let signup = $derived(mode === 'signup');
	let name = $state('');
	let email = $state('');
	let password = $state('');
	let showPassword = $state(false);
	let loading = $state(false);
	let error = $state('');
	let otherPage = $derived(
		`${signup ? '/login' : '/signup'}${redirectTo === '/dashboard' ? '' : `?redirectTo=${encodeURIComponent(redirectTo)}`}`
	);

	async function submit(event: SubmitEvent) {
		event.preventDefault();
		if (loading) return;
		loading = true;
		error = '';
		try {
			const result = signup
				? await authClient.signUp.email({ name: name.trim(), email: email.trim(), password })
				: await authClient.signIn.email({ email: email.trim(), password });
			if (result.error) {
				error =
					result.error.message ||
					`Unable to ${signup ? 'create your account' : 'log in'}. Please try again.`;
				return;
			}
			password = '';
			await goto(redirectTo, { refreshAll: true });
		} catch {
			error = 'Unable to connect. Please try again.';
		} finally {
			loading = false;
		}
	}
</script>

<svelte:head>
	<title>{signup ? 'Create an account' : 'Log in'} — VOE</title>
	<meta
		name="description"
		content={signup
			? 'Create your VOE account and keep your environment variables encrypted and in sync.'
			: 'Log in to your VOE environment vault.'}
	/>
</svelte:head>

<div class="site-shell auth-shell">
	<SiteHeader auth />
	<main id="main-content" class="auth-main">
		<section class="auth-panel" aria-labelledby="auth-title">
			<h1 id="auth-title">{signup ? 'Sign up' : 'Log in'}</h1>
			<form onsubmit={submit} aria-describedby={error ? 'auth-error' : undefined}>
				<fieldset disabled={loading}>
					{#if signup}
						<div class="field">
							<Label for="name">Name</Label><Input
								id="name"
								name="name"
								autocomplete="name"
								placeholder="Your name"
								bind:value={name}
								required
								class="h-11"
							/>
						</div>
					{/if}
					<div class="field">
						<Label for="email">Email</Label><Input
							id="email"
							name="email"
							type="email"
							autocomplete="email"
							placeholder="you@example.com"
							bind:value={email}
							required
							class="h-11"
						/>
					</div>
					<div class="field">
						<Label for="password">Password</Label>
						<div class="password-field">
							<Input
								id="password"
								name="password"
								type={showPassword ? 'text' : 'password'}
								autocomplete={signup ? 'new-password' : 'current-password'}
								minlength={signup ? 8 : undefined}
								maxlength={128}
								aria-describedby={signup ? 'password-hint' : undefined}
								bind:value={password}
								required
								class="h-11 pr-11"
							/>
							<button
								type="button"
								class="password-toggle"
								onclick={() => (showPassword = !showPassword)}
								aria-label={showPassword ? 'Hide password' : 'Show password'}
								aria-pressed={showPassword}
								>{#if showPassword}<EyeOff class="size-4" />{:else}<Eye
										class="size-4"
									/>{/if}</button
							>
						</div>
						{#if signup}<p id="password-hint" class="password-hint">At least 8 characters.</p>{/if}
					</div>
					{#if error}<p id="auth-error" role="alert" class="form-error">{error}</p>{/if}
					<Button type="submit" class="mt-1 h-11 w-full" disabled={loading}
						>{#if loading}<LoaderCircle class="size-4 animate-spin" />{signup
								? 'Creating account…'
								: 'Logging in…'}{:else}{signup ? 'Create account' : 'Log in'}{/if}</Button
					>
				</fieldset>
			</form>
			<p class="other-page">
				{signup ? 'Already have an account?' : 'Don’t have an account?'}
				<a href={otherPage}>{signup ? 'Log in' : 'Sign up'}</a>
			</p>
		</section>
	</main>
	<SiteFooter />
</div>

<style>
	.auth-shell {
		min-height: 100svh;
		display: flex;
		flex-direction: column;
	}
	.auth-main {
		display: flex;
		flex: 1;
		justify-content: center;
		align-items: center;
		padding: 48px 0 64px;
	}
	.auth-panel {
		width: 100%;
		max-width: 348px;
	}
	h1 {
		font-size: 30px;
		line-height: 1.2;
		letter-spacing: -0.04em;
		font-weight: 550;
	}
	form {
		margin-top: 32px;
	}
	fieldset {
		display: flex;
		flex-direction: column;
		gap: 20px;
	}
	.field {
		display: flex;
		flex-direction: column;
		gap: 9px;
	}
	.field :global(label) {
		font-size: 13px;
		font-weight: 500;
	}
	.field :global(input) {
		font-size: 13px;
		background: var(--card);
	}
	.password-field {
		position: relative;
	}
	.password-toggle {
		position: absolute;
		right: 3px;
		top: 3px;
		width: 38px;
		height: 38px;
		display: flex;
		align-items: center;
		justify-content: center;
		color: var(--muted-foreground);
	}
	.password-toggle:hover {
		color: var(--foreground);
	}
	.password-hint {
		color: var(--muted-foreground);
		font-size: 12px;
	}
	.form-error {
		color: var(--destructive);
		font-size: 12px;
		line-height: 1.6;
	}
	.other-page {
		margin-top: 25px;
		font-size: 13px;
		text-align: center;
		color: var(--muted-foreground);
	}
	.other-page a {
		margin-left: 4px;
		color: var(--foreground);
	}
	.other-page a:hover {
		text-decoration: underline;
		text-underline-offset: 4px;
	}
	@media (max-width: 640px) {
		.auth-main {
			align-items: flex-start;
			padding: 40px 0 48px;
		}
		h1 {
			font-size: 30px;
		}
		.field :global(input) {
			font-size: 16px;
		}
	}
</style>
