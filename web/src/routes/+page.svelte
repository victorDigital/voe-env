<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { authClient } from '$lib/auth-client';
	import { Button } from '$lib/components/ui/button/index.js';
	import * as Card from '$lib/components/ui/card/index.js';
	import { Input } from '$lib/components/ui/input/index.js';
	import { Label } from '$lib/components/ui/label/index.js';
	import type { PageData } from './$types';

	let { data }: { data: PageData } = $props();
	let creatingAccount = $state(false);
	let name = $state('');
	let email = $state('');
	let password = $state('');
	let loading = $state(false);
	let error = $state('');
	let installerPlatform = $state<'unix' | 'windows'>('unix');
	let copied = $state(false);
	let copyError = $state('');
	let installCommand = $derived(
		installerPlatform === 'windows'
			? `& ([scriptblock]::Create((irm '${page.url.origin.replaceAll("'", "''")}/install.ps1'))) -BaseUrl '${page.url.origin.replaceAll("'", "''")}'`
			: `curl -fsSL ${shellQuote(`${page.url.origin}/install.sh`)} | sh -s -- ${shellQuote(page.url.origin)}`
	);

	function shellQuote(value: string) {
		return `'${value.replaceAll("'", "'\\''")}'`;
	}

	async function copyInstallCommand() {
		copyError = '';
		try {
			if (navigator.clipboard && window.isSecureContext) {
				await navigator.clipboard.writeText(installCommand);
			} else {
				const input = document.createElement('textarea');
				input.value = installCommand;
				input.style.position = 'fixed';
				input.style.opacity = '0';
				document.body.appendChild(input);
				input.select();
				const success = document.execCommand('copy');
				input.remove();
				if (!success) throw new Error('Copy failed');
			}
			copied = true;
		} catch {
			copyError = 'Select and copy the command above.';
		}
	}

	function selectInstaller(platform: 'unix' | 'windows') {
		installerPlatform = platform;
		copied = false;
		copyError = '';
	}

	async function submit(event: SubmitEvent) {
		event.preventDefault();
		if (loading) return;

		loading = true;
		error = '';

		try {
			const result = creatingAccount
				? await authClient.signUp.email({ name: name.trim(), email: email.trim(), password })
				: await authClient.signIn.email({ email: email.trim(), password });

			if (result.error) {
				error = result.error.message || 'Unable to sign in. Please try again.';
				return;
			}

			password = '';
			await goto(data.redirectTo, { invalidateAll: true });
		} catch {
			error = 'Unable to connect. Please try again.';
		} finally {
			loading = false;
		}
	}

	function toggleMode() {
		creatingAccount = !creatingAccount;
		password = '';
		error = '';
	}
</script>

<svelte:head>
	<title>{creatingAccount ? 'Create account' : 'Sign in'} | VOE</title>
</svelte:head>

<div class="flex min-h-screen flex-col items-center justify-center gap-6 bg-background p-4">
	<Card.Root class="w-full max-w-md">
		<Card.Header class="text-center">
			<Card.Title class="text-2xl font-semibold">
				{creatingAccount ? 'Create account' : 'Welcome'}
			</Card.Title>
			<Card.Description>
				{creatingAccount
					? 'Create an account to access your environment vault'
					: 'Sign in to access your environment vault'}
			</Card.Description>
		</Card.Header>
		<Card.Content>
			<form onsubmit={submit}>
				<fieldset disabled={loading} class="space-y-4">
					{#if creatingAccount}
						<div class="space-y-2">
							<Label for="name">Name</Label>
							<Input id="name" name="name" autocomplete="name" bind:value={name} required />
						</div>
					{/if}
					<div class="space-y-2">
						<Label for="email">Email</Label>
						<Input
							id="email"
							name="email"
							type="email"
							autocomplete="email"
							bind:value={email}
							required
						/>
					</div>
					<div class="space-y-2">
						<Label for="password">Password</Label>
						<Input
							id="password"
							name="password"
							type="password"
							autocomplete={creatingAccount ? 'new-password' : 'current-password'}
							minlength={creatingAccount ? 8 : undefined}
							maxlength={128}
							aria-describedby={creatingAccount ? 'password-hint' : undefined}
							bind:value={password}
							required
						/>
						{#if creatingAccount}
							<p id="password-hint" class="text-sm text-muted-foreground">
								Use at least 8 characters.
							</p>
						{/if}
					</div>
					{#if error}
						<p role="alert" class="text-sm text-destructive">{error}</p>
					{/if}
					<Button type="submit" class="w-full" disabled={loading}>
						{loading ? 'Please wait…' : creatingAccount ? 'Create account' : 'Sign in'}
					</Button>
				</fieldset>
			</form>
			<Button variant="link" class="mt-2 w-full" onclick={toggleMode} disabled={loading}>
				{creatingAccount ? 'Already have an account? Sign in' : 'Need an account? Create one'}
			</Button>
		</Card.Content>
	</Card.Root>
	<Card.Root class="w-full max-w-2xl">
		<Card.Header>
			<Card.Title>Install the CLI</Card.Title>
			<Card.Description>
				One command to install <code>ve</code> and connect it to this site.
			</Card.Description>
		</Card.Header>
		<Card.Content class="space-y-3">
			<div class="flex items-center justify-between gap-2">
				<div class="flex gap-1" role="group" aria-label="Installer platform">
					<Button
						size="sm"
						variant={installerPlatform === 'unix' ? 'secondary' : 'ghost'}
						aria-pressed={installerPlatform === 'unix'}
						onclick={() => selectInstaller('unix')}
					>
						macOS / Linux
					</Button>
					<Button
						size="sm"
						variant={installerPlatform === 'windows' ? 'secondary' : 'ghost'}
						aria-pressed={installerPlatform === 'windows'}
						onclick={() => selectInstaller('windows')}
					>
						Windows
					</Button>
				</div>
				<Button size="sm" variant="outline" onclick={copyInstallCommand}>
					{copied ? 'Copied' : 'Copy'}
				</Button>
			</div>
			<pre class="overflow-x-auto rounded-md bg-muted p-3 text-xs"><code>{installCommand}</code
				></pre>
			{#if copyError}
				<p role="alert" class="text-sm text-destructive">{copyError}</p>
			{/if}
			<p class="text-sm text-muted-foreground">
				Run in {installerPlatform === 'windows' ? 'PowerShell' : 'your terminal'}. Then open a new
				terminal and run <code>ve auth</code>.
			</p>
		</Card.Content>
	</Card.Root>
</div>
