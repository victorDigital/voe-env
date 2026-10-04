import { testDatabaseURL } from './database';
const child = Bun.spawn(['bun', 'run', 'dev', '--host', '127.0.0.1', '--port', '5174'], {
	stdout: 'inherit',
	stderr: 'inherit',
	env: {
		...process.env,
		DATABASE_URL: testDatabaseURL().href,
		BETTER_AUTH_URL: 'http://localhost:5174',
		PUBLIC_BETTER_AUTH_URL: '',
		BETTER_AUTH_SECRET: 'voe-passwordless-local-test-secret-only',
		EMAIL_API_KEY: '',
		EMAIL_FROM: ''
	}
});
process.exit(await child.exited);
