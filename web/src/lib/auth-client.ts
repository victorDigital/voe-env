import { PUBLIC_BETTER_AUTH_URL } from '$app/env/public';
import {
	deviceAuthorizationClient,
	organizationClient,
	magicLinkClient
} from 'better-auth/client/plugins';
import { passkeyClient } from '@better-auth/passkey/client';
import { createAuthClient } from 'better-auth/svelte';
import { ac, roles } from './permissions';
export const authClient = createAuthClient({
	baseURL: PUBLIC_BETTER_AUTH_URL || undefined,
	plugins: [
		deviceAuthorizationClient(),
		organizationClient({ ac, roles }),
		magicLinkClient(),
		passkeyClient()
	]
});
