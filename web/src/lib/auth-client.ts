import { PUBLIC_BETTER_AUTH_URL } from '$app/env/public';
import { deviceAuthorizationClient } from 'better-auth/client/plugins';
import { createAuthClient } from 'better-auth/svelte';
export const authClient = createAuthClient({
	baseURL: PUBLIC_BETTER_AUTH_URL || undefined,
	plugins: [deviceAuthorizationClient()]
});
