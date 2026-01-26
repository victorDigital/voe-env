<script>
	import { authClient } from '$lib/auth-client';
</script>

<p>goto</p>
<button
	onclick={async () => {
		const { data, error } = await authClient.signIn.oauth2({
			providerId: 'voe-auth', // required
			callbackURL: '/dashboard',
			disableRedirect: false,
			scopes: ['openid', 'profile', 'email']
		});
	}}
>
	voe auth
</button>
