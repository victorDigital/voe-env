import { defineEnvVars } from '@sveltejs/kit/env';

const optional = (value: string | undefined) => value;

export const variables = defineEnvVars({
	EMAIL_API_KEY: { schema: optional },
	EMAIL_FROM: { schema: optional },
	DATABASE_URL: { schema: optional },
	BETTER_AUTH_URL: { schema: optional },
	BETTER_AUTH_SECRET: { schema: optional },
	VOE_CLI_RELEASE_URL: { schema: optional },
	PUBLIC_BETTER_AUTH_URL: { public: true, static: true, schema: optional }
});
