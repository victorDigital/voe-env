<script lang="ts">
	import { page } from '$app/state';
	import RiCheckLine from 'remixicon-svelte/icons/check-line';
	import RiFileCopyLine from 'remixicon-svelte/icons/file-copy-line';
	import { Button } from '#lib/components/ui/button/index.ts';
	import SiteHeader from '#lib/components/SiteHeader.svelte';
	import SiteFooter from '#lib/components/SiteFooter.svelte';
	import type { PageData } from './$types';

	let { data }: { data: PageData } = $props();
	let platform = $state<'unix' | 'windows'>('unix');
	let copied = $state(false);
	let copyError = $state('');
	let installCommand = $derived(
		platform === 'windows'
			? `& ([scriptblock]::Create((irm '${page.url.origin.replaceAll("'", "''")}/install.ps1'))) -BaseUrl '${page.url.origin.replaceAll("'", "''")}'`
			: `curl -fsSL ${shellQuote(`${page.url.origin}/install.sh`)} | sh -s -- ${shellQuote(page.url.origin)}`
	);
	const commands = [
		{ command: 've auth', description: 'Sign in' },
		{ command: 've init', description: 'Choose a workspace' },
		{ command: 've push', description: 'Upload .env' },
		{ command: 've pull', description: 'Download .env' },
		{ command: 've update', description: 'Update CLI' }
	];

	function shellQuote(value: string) {
		return `'${value.replaceAll("'", "'\\''")}'`;
	}

	function selectPlatform(value: 'unix' | 'windows') {
		platform = value;
		copied = false;
		copyError = '';
	}

	async function copyCommand() {
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
			copyError = 'Select the command and copy it to your clipboard.';
		}
	}
</script>

<svelte:head>
	<title>VOE · Encrypted .env files</title>
	<meta
		name="description"
		content="Sync encrypted .env files across machines and collaborate in passwordless workspaces."
	/>
</svelte:head>

<div class="site-shell landing-shell">
	<SiteHeader signedIn={data.signedIn} />
	<main id="main-content">
		<div class="overview">
			<section class="intro" aria-labelledby="page-title">
				<h1 id="page-title">Encrypted<br /><code>.env</code> files.</h1>
				<p>Sync encrypted .env files across machines and collaborate in passwordless workspaces.</p>
			</section>
			<section id="install" class="install-section" aria-labelledby="install-title">
				<div class="section-heading">
					<h2 id="install-title">Install CLI</h2>
					<div class="platform-switch" role="group" aria-label="Installer platform">
						<Button
							variant={platform === 'unix' ? 'secondary' : 'ghost'}
							size="sm"
							class="platform-button"
							aria-pressed={platform === 'unix'}
							onclick={() => selectPlatform('unix')}>macOS / Linux</Button
						>
						<Button
							variant={platform === 'windows' ? 'secondary' : 'ghost'}
							size="sm"
							class="platform-button"
							aria-pressed={platform === 'windows'}
							onclick={() => selectPlatform('windows')}>Windows</Button
						>
					</div>
				</div>
				<div class="install-command">
					<span class="prompt" aria-hidden="true">{platform === 'windows' ? '>' : '$'}</span>
					<input
						readonly
						aria-label="Installation command"
						value={installCommand}
						spellcheck="false"
					/>
					<Button
						variant="ghost"
						class="copy-command h-auto self-stretch border-0 border-l px-3"
						onclick={copyCommand}
						aria-label={copied ? 'Command copied' : 'Copy install command'}
					>
						{#if copied}<RiCheckLine class="size-4" aria-hidden="true" />{:else}<RiFileCopyLine
								class="size-4"
								aria-hidden="true"
							/>{/if}
						<span aria-live="polite">{copied ? 'Copied' : 'Copy'}</span>
					</Button>
				</div>
				{#if copyError}<p role="alert" class="copy-error">{copyError}</p>{/if}
				<p class="install-note">
					Run in {platform === 'windows' ? 'PowerShell' : 'your terminal'}. Open a new terminal
					after installation.
				</p>
			</section>
		</div>
		<section class="commands" aria-labelledby="commands-title">
			<h2 id="commands-title">Commands</h2>
			<dl>
				{#each commands as item (item.command)}
					<div>
						<dt><code>{item.command}</code></dt>
						<dd>{item.description}</dd>
					</div>
				{/each}
			</dl>
		</section>
	</main>
	<SiteFooter />
</div>

<style>
	.landing-shell {
		--landing-accent: color-mix(in oklch, var(--primary) 75%, var(--foreground));
		max-width: 1040px;
	}
	.overview {
		display: grid;
		grid-template-columns: minmax(0, 0.85fr) minmax(0, 1.15fr);
		align-items: center;
		gap: 64px;
		padding: 80px 0 64px;
	}
	h1 {
		font-size: clamp(40px, 4.5vw, 60px);
		line-height: 1.05;
		font-weight: 500;
		letter-spacing: -0.06em;
	}
	h1 code {
		font-family: var(--font-mono);
		font-size: 0.9em;
		letter-spacing: -0.075em;
		color: var(--landing-accent);
	}
	.intro p {
		margin-top: 20px;
		max-width: 340px;
		font-size: 15px;
		line-height: 1.65;
		color: var(--muted-foreground);
	}
	h2 {
		font-size: 14px;
		font-weight: 550;
		line-height: 1.5;
	}
	.section-heading {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 16px;
		margin-bottom: 16px;
	}
	.platform-switch {
		display: flex;
		gap: 2px;
	}
	.platform-switch :global(.platform-button) {
		height: 36px;
		font-size: 12px;
		font-weight: 400;
		color: var(--muted-foreground);
	}
	.platform-switch :global(.platform-button[aria-pressed='true']) {
		color: var(--foreground);
		box-shadow: inset 0 -2px var(--landing-accent);
	}
	.install-command {
		display: flex;
		align-items: center;
		min-width: 0;
		min-height: 60px;
		border: 1px solid var(--border);
		background: var(--muted);
	}
	.prompt {
		padding-left: 16px;
		font-family: var(--font-mono);
		font-size: 13px;
		color: var(--muted-foreground);
	}
	.install-command input {
		min-width: 0;
		width: 100%;
		padding: 20px 12px;
		font-family: var(--font-mono);
		font-size: 12px;
		line-height: 1.5;
		background: transparent;
	}
	.install-command:focus-within {
		outline: 2px solid var(--ring);
		outline-offset: 3px;
	}
	.install-command input:focus-visible {
		outline: none;
	}
	.install-command :global(.copy-command) {
		min-width: 80px;
		font-size: 12px;
		font-weight: 400;
		border-left-color: var(--border);
		background: var(--background);
	}
	.install-command :global(.copy-command:hover) {
		background: var(--accent);
	}
	.install-note {
		margin-top: 14px;
		color: var(--muted-foreground);
		font-size: 12px;
		line-height: 1.65;
	}
	.copy-error {
		margin-top: 12px;
		color: var(--destructive);
		font-size: 13px;
	}
	.commands {
		display: grid;
		grid-template-columns: minmax(0, 0.85fr) minmax(0, 1.15fr);
		gap: 64px;
		padding: 32px 0 48px;
		border-top: 1px solid var(--border);
	}
	.commands h2 {
		padding-top: 12px;
	}
	dl > div {
		display: grid;
		grid-template-columns: 104px minmax(0, 1fr);
		align-items: baseline;
		gap: 24px;
		padding: 12px 0;
		border-bottom: 1px solid var(--border);
		font-size: 13px;
		line-height: 1.5;
	}
	dl > div:last-child {
		border-bottom: 0;
	}
	dt code {
		font-family: var(--font-mono);
		font-size: 12px;
	}
	dd {
		color: var(--muted-foreground);
	}
	@media (max-width: 800px) {
		.overview,
		.commands {
			grid-template-columns: minmax(0, 1fr);
			gap: 36px;
		}
		.overview {
			padding: 48px 0 36px;
		}
		.intro p {
			max-width: 440px;
			font-size: 14px;
		}
		.commands {
			gap: 12px;
			padding: 24px 0 36px;
		}
		.commands h2 {
			padding-top: 0;
		}
	}
	@media (max-width: 420px) {
		.section-heading {
			align-items: flex-start;
			flex-direction: column;
			gap: 12px;
		}
		.prompt {
			padding-left: 12px;
		}
		.install-command input {
			padding: 18px 10px;
		}
		dl > div {
			grid-template-columns: 90px minmax(0, 1fr);
			gap: 20px;
		}
	}
</style>
