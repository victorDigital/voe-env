import { appendFile } from 'node:fs/promises';

const mailbox = process.env.VOE_TEST_MAILBOX || '';
if (process.env.BETTER_AUTH_URL !== 'http://localhost:5174' || !mailbox)
	throw new Error('Email interception is only available in the local test server.');
globalThis.fetch = new Proxy(globalThis.fetch, {
	async apply(target, thisArg, args) {
		const [input, init] = args;
		const url = input instanceof Request ? input.url : String(input);
		if (url === 'https://api.resend.com/emails') {
			await appendFile(mailbox, `${init?.body}\n`);
			return Response.json({ id: crypto.randomUUID() });
		}
		return Reflect.apply(target, thisArg, args);
	}
});
