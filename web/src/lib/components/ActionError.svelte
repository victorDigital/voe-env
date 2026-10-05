<script lang="ts">
	import { Button } from '#lib/components/ui/button/index.ts';
	import { signInAndUnlock } from '#lib/vault-client.ts';
	let { error = $bindable('') }: { error?: string } = $props();
	let verifying = $state(false);
	async function verify() {
		verifying = true;
		try {
			await signInAndUnlock();
			error = '';
		} catch (e) {
			error = (e as Error).message;
		} finally {
			verifying = false;
		}
	}
</script>

{#if error}<div role="alert" class="space-y-2 text-xs text-destructive">
		<p>{error}</p>
		{#if /(?:verify|unlock).*passkey/i.test(error)}<Button
				variant="outline"
				size="sm"
				disabled={verifying}
				onclick={verify}>{verifying ? 'Verifying…' : 'Verify with passkey'}</Button
			>{/if}
	</div>{/if}
