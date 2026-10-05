import { testDatabaseURL } from './database';
import { writeFile } from 'node:fs/promises';
const mailbox = '/tmp/voe-test-mailbox.jsonl';
await writeFile(mailbox, '');
const child = Bun.spawn(['bun', 'run', 'dev', '--host', '127.0.0.1', '--port', '5174'], {
	stdout: 'inherit',
	stderr: 'inherit',
	env: {
		...process.env,
		DATABASE_URL: testDatabaseURL().href,
		BETTER_AUTH_URL: 'http://localhost:5174',
		PUBLIC_BETTER_AUTH_URL: '',
		BETTER_AUTH_SECRET: 'voe-passwordless-local-test-secret-only',
		EMAIL_API_KEY: 'test-only-intercepted',
		EMAIL_FROM: 'VOE <test@example.test>',
		VOE_TEST_MAILBOX: mailbox,
		NODE_OPTIONS: `--import ${new URL('./email-interceptor.mjs', import.meta.url).href}`
	}
});
process.exit(await child.exited);
