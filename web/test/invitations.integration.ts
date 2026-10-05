import { testDatabaseURL } from './database';
import assert from 'node:assert/strict';
import { createHmac, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import postgres from 'postgres';

const base = 'http://localhost:5174';
const sql = postgres(testDatabaseURL().href);
const prefix = randomUUID();
const owner = `${prefix}-owner`;
const sessionToken = randomUUID();
const cookie = `better-auth.session_token=${encodeURIComponent(sessionToken + '.' + createHmac('sha256', 'voe-passwordless-local-test-secret-only').update(sessionToken).digest('base64'))}`;
const emails = async (email: string) =>
	(await readFile('/tmp/voe-test-mailbox.jsonl', 'utf8'))
		.trim()
		.split('\n')
		.filter(Boolean)
		.map((s) => JSON.parse(s))
		.filter((m) => m.to.includes(email));
async function post(path: string, body: unknown, session = '', origin = base) {
	return fetch(base + path, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
			origin,
			...(session ? { cookie: session } : {})
		},
		body: JSON.stringify(body),
		redirect: 'manual'
	});
}
async function ok(response: Response) {
	const data = await response.json();
	assert.equal(response.status, 200, JSON.stringify(data));
	return data;
}
const sessionCookie = (r: Response) =>
	r.headers
		.getSetCookie()
		.map((v) => v.split(';')[0])
		.join('; ');
let orgId = '';
const invitationIds: string[] = [];
async function invite(label: string) {
	const email = `${prefix}-${label}@example.test`;
	const invitation = await ok(
		await post(
			'/api/auth/organization/invite-member',
			{ organizationId: orgId, email, role: 'viewer' },
			cookie
		)
	);
	invitationIds.push(invitation.id);
	assert.equal(invitation.token, undefined);
	const messages = await emails(email);
	assert.equal(messages.length, 1);
	const url = new URL(messages[0].text.match(/http:\/\/localhost:5174\/invite\/\S+/)[0]);
	const token = url.searchParams.get('token')!;
	assert.equal(token.length, 43);
	return {
		id: invitation.id,
		email,
		url,
		token,
		body: { invitationId: invitation.id, token, name: 'Invited person' }
	};
}
try {
	await sql`insert into "user" (id,name,email,email_verified) values (${owner},'Owner',${owner + '@example.test'},true)`;
	await sql`insert into session (id,user_id,token,expires_at,updated_at) values (${randomUUID()},${owner},${sessionToken},now()+interval '1 hour',now())`;
	const org = await ok(
		await post('/api/auth/organization/create', { name: 'Invitation test', slug: prefix }, cookie)
	);
	orgId = org.id;
	const fresh = await invite('new');
	const loaded = await fetch(fresh.url, { redirect: 'manual' });
	assert.equal(loaded.status, 200);
	assert.equal(loaded.headers.get('referrer-policy'), 'no-referrer');
	const html = await loaded.text();
	assert.ok(html.includes('Your name') && html.includes('Join workspace'));
	assert.equal((await sql`select id from "user" where email=${fresh.email}`).length, 0);
	assert.equal(
		(await post('/api/auth/sign-in/invitation', { ...fresh.body, token: 'A'.repeat(43) })).status,
		400
	);
	assert.equal(
		(await post('/api/auth/sign-in/invitation', { ...fresh.body, name: ' ' })).status,
		400
	);
	assert.equal((await post('/api/auth/sign-in/invitation', fresh.body, cookie)).status, 403);
	assert.equal(
		(await post('/api/auth/sign-in/invitation', fresh.body, '', 'https://attacker.example')).status,
		403
	);
	const signedIn = await post('/api/auth/sign-in/invitation', {
		...fresh.body,
		email: 'attacker@example.test'
	});
	await ok(signedIn);
	const newCookie = sessionCookie(signedIn);
	assert.ok(newCookie.includes('better-auth.session_token='));
	const [newUser] = await sql`select * from "user" where email=${fresh.email}`;
	assert.equal(newUser.name, 'Invited person');
	assert.equal(newUser.email_verified, true);
	await ok(
		await post('/api/auth/organization/accept-invitation', { invitationId: fresh.id }, newCookie)
	);
	assert.equal(
		(await sql`select id from member where organization_id=${orgId} and user_id=${newUser.id}`)
			.length,
		1
	);
	assert.equal(
		(await sql`select user_id from encryption_identity where user_id=${newUser.id}`).length,
		0
	);
	assert.equal((await emails(fresh.email)).length, 1);
	assert.equal((await post('/api/auth/sign-in/invitation', fresh.body)).status, 400);

	const expired = await invite('expired');
	await sql`update invitation set expires_at=now()-interval '1 second' where id=${expired.id}`;
	assert.equal((await post('/api/auth/sign-in/invitation', expired.body)).status, 400);
	const cancelled = await invite('cancelled');
	await ok(
		await post('/api/auth/organization/cancel-invitation', { invitationId: cancelled.id }, cookie)
	);
	assert.equal((await post('/api/auth/sign-in/invitation', cancelled.body)).status, 400);
	const resent = await invite('resent');
	await ok(
		await post(
			'/api/auth/organization/invite-member',
			{ organizationId: orgId, email: resent.email, role: 'viewer', resend: true },
			cookie
		)
	);
	assert.equal((await post('/api/auth/sign-in/invitation', resent.body)).status, 400);
	const resentMessages = await emails(resent.email);
	const replacement = new URL(
		resentMessages[1].text.match(/http:\/\/localhost:5174\/invite\/\S+/)[0]
	).searchParams.get('token');
	await ok(await post('/api/auth/sign-in/invitation', { ...resent.body, token: replacement }));

	const concurrent = await invite('concurrent');
	const attempts = await Promise.all([
		post('/api/auth/sign-in/invitation', concurrent.body),
		post('/api/auth/sign-in/invitation', concurrent.body)
	]);
	assert.deepEqual(attempts.map((r) => r.status).sort(), [200, 400]);
	const unverified = await invite('unverified');
	const unverifiedId = randomUUID();
	const oldSession = randomUUID();
	await sql`insert into "user" (id,name,email,email_verified) values (${unverifiedId},'Existing name',${unverified.email},false)`;
	await sql`insert into session (id,user_id,token,expires_at,updated_at) values (${oldSession},${unverifiedId},${randomUUID()},now()+interval '1 hour',now())`;
	await ok(await post('/api/auth/sign-in/invitation', unverified.body));
	const [promoted] = await sql`select name,email_verified from "user" where id=${unverifiedId}`;
	assert.equal(promoted.email_verified, true);
	assert.equal(promoted.name, 'Existing name');
	assert.equal((await sql`select id from session where id=${oldSession}`).length, 0);
	const tokenExpired = await invite('token-expired');
	await sql`update verification set expires_at=now()-interval '1 second' where identifier=${'invitation-auth:' + tokenExpired.id}`;
	assert.equal((await post('/api/auth/sign-in/invitation', tokenExpired.body)).status, 400);
	const signupEmail = `${prefix}-ordinary@example.test`;
	await ok(
		await post('/api/auth/sign-in/magic-link', {
			email: signupEmail,
			name: 'Ordinary signup',
			callbackURL: '/dashboard/env'
		})
	);
	assert.equal((await emails(signupEmail)).length, 1);
	assert.equal((await sql`select id from "user" where email=${signupEmail}`).length, 0);
	console.log(
		'PASS: invitation signup uses one email; proof is single-use, bound to the recipient, and rejects expiry, cancellation, resend, replay, cross-origin requests, and the wrong account; ordinary signup still verifies email'
	);
} finally {
	if (orgId) await sql`delete from organization where id=${orgId}`;
	await sql`delete from "user" where email like ${prefix + '%'}`;
	for (const id of invitationIds)
		await sql`delete from verification where identifier=${'invitation-auth:' + id}`;
	await sql.end();
}
