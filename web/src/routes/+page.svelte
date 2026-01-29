<script>
	import { authClient } from '$lib/auth-client';
	import { Button } from '$lib/components/ui/button/index.js';
	import * as Card from '$lib/components/ui/card/index.js';
</script>

<div class="flex min-h-screen items-center justify-center bg-background p-4">
	<Card.Root class="w-full max-w-md">
		<Card.Header class="text-center">
			<Card.Title class="text-2xl font-semibold">Welcome</Card.Title>
			<Card.Description>Sign in to access your environment vault</Card.Description>
		</Card.Header>
		<Card.Content>
			<Button
				class="w-full"
				onclick={async () => {
					await authClient.signIn.oauth2({
						providerId: 'voe-auth',
						callbackURL: '/dashboard',
						disableRedirect: false,
						scopes: ['openid', 'profile', 'email']
					});
				}}
			>
				Sign in with Voe Auth
			</Button>
		</Card.Content>
	</Card.Root>
</div>
