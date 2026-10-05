import { testDatabaseURL } from './database';
import assert from 'node:assert/strict';
import { createHmac, randomUUID, generateKeyPairSync, createHash, sign } from 'node:crypto';
import postgres from 'postgres';
import {
	identityKeyPair,
	randomKey,
	seal,
	wrapTo,
	unseal,
	unwrapFrom,
	bytes,
	encode,
	derivePrf
} from '../src/lib/vault-crypto';
import { context, folderContext, secretContext, orgContext } from '../src/lib/vault-format';
const base = process.env.VOE_TEST_URL || 'http://localhost:5174';
const database = testDatabaseURL();
if (!base.startsWith('http://localhost:') || database.pathname !== '/voe_passwordless_test')
	throw new Error('Integration tests require the isolated local database');
const sql = postgres(database.href);
const prefix = randomUUID();
const actors: Record<
	string,
	{
		id: string;
		token: string;
		cookie: string;
		session: string;
		pair: Awaited<ReturnType<typeof identityKeyPair>>;
	}
> = {};
const cookieSignature = (token: string) =>
	`better-auth.session_token=${encodeURIComponent(token + '.' + createHmac('sha256', 'voe-passwordless-local-test-secret-only').update(token).digest('base64'))}`;
async function actor(name: string) {
	const id = `${prefix}-${name}`;
	const token = randomUUID();
	const session = randomUUID();
	const pair = await identityKeyPair();
	await sql`insert into "user" (id,name,email,email_verified) values (${id},${name},${id + '@example.test'},true)`;
	await sql`insert into session (id,user_id,token,expires_at,updated_at) values (${session},${id},${token},now()+interval '1 hour',now())`;
	await sql`insert into encryption_identity (user_id,public_key,encrypted_private_key,recovery_envelope,recovery_auth_hash) values (${id},${pair.publicKey},'unused','unused',${'0'.repeat(64)})`;
	await sql`insert into passkey_verification (session_id,recovery) values (${session},true)`;
	actors[name] = { id, token, cookie: cookieSignature(token), session, pair };
}
async function call(name: string | null, path: string, body?: unknown, bearer?: string) {
	const response = await fetch(base + path, {
		method: body ? 'POST' : 'GET',
		headers: {
			...(name ? { cookie: actors[name].cookie } : {}),
			...(body ? { 'Content-Type': 'application/json', origin: base } : {}),
			...(bearer ? { authorization: `Bearer ${bearer}` } : {})
		},
		body: body ? JSON.stringify(body) : undefined,
		redirect: 'manual'
	});
	const data = await response.json().catch(() => null);
	return { status: response.status, data };
}
async function expectStatus(
	expected: number,
	name: string | null,
	path: string,
	body?: unknown,
	bearer?: string
) {
	const result = await call(name, path, body, bearer);
	assert.equal(result.status, expected, JSON.stringify({ path, data: result.data }));
	return result.data;
}
try {
	for (const name of ['owner', 'admin', 'member', 'viewer', 'outsider']) await actor(name);
	const org = await expectStatus(200, 'owner', '/api/auth/organization/create', {
		name: 'Test workspace',
		slug: prefix
	});
	const orgId = org.id;
	assert.ok(orgId);
	for (const role of ['admin', 'member', 'viewer'])
		await sql`insert into member (id,organization_id,user_id,role,created_at) values (${randomUUID()},${orgId},${actors[role].id},${role},now())`;
	const route = `/api/workspaces/${orgId}`;
	const root = randomUUID(),
		folder = randomUUID(),
		secret = randomUUID();
	let orgKey = randomKey(),
		folderKey = randomKey();
	const folders = [
		{
			id: root,
			name: '',
			parentId: null,
			wrappedKey: await seal(orgKey, randomKey(), folderContext(orgId, root, 1))
		},
		{
			id: folder,
			name: 'production',
			parentId: root,
			wrappedKey: await seal(orgKey, folderKey, folderContext(orgId, folder, 1))
		}
	];
	const secrets = [
		{
			id: secret,
			folderId: folder,
			name: 'API_KEY',
			encryptedValue: await seal(
				folderKey,
				bytes('test-secret-only'),
				secretContext(orgId, folder, secret, 'API_KEY', 1)
			)
		}
	];
	const ownerRecipient = `user:${actors.owner.id}`;
	const initialize = {
		action: 'initialize',
		revision: 0,
		epoch: 1,
		folders,
		secrets,
		envelopes: [
			{
				recipient: ownerRecipient,
				wrappedKey: await wrapTo(
					actors.owner.pair.publicKey,
					orgKey,
					orgContext(orgId, ownerRecipient, 1)
				),
				identityBinding: await seal(
					orgKey,
					bytes(actors.owner.pair.publicKey),
					context('recipient', orgId, ownerRecipient, 1)
				)
			}
		]
	};
	await expectStatus(200, 'owner', route, initialize);
	await expectStatus(401, null, route);
	await expectStatus(403, 'outsider', route);
	let snapshot = await expectStatus(200, 'viewer', route);
	assert.equal(snapshot.secrets.length, 1);
	await expectStatus(403, 'viewer', route, { ...snapshot, action: 'save' });
	await expectStatus(403, 'member', route, { ...snapshot, action: 'save' });
	await sql`delete from passkey_verification where session_id = ${actors.owner.session}`;
	await expectStatus(403, 'owner', route, { ...snapshot, action: 'save' });
	await sql`insert into passkey_verification (session_id,recovery) values (${actors.owner.session},true)`;
	await expectStatus(403, 'member', route, {
		action: 'remove-member',
		revision: 1,
		userId: actors.viewer.id
	});
	await expectStatus(403, 'admin', route, {
		action: 'role',
		revision: 1,
		userId: actors.admin.id,
		role: 'owner'
	});
	await expectStatus(400, 'owner', route, {
		action: 'save',
		revision: 1,
		epoch: 1,
		folders: 'invalid',
		secrets: []
	});
	await expectStatus(409, 'owner', '/api/identity', { action: 'reset', confirm: 'RESET' });
	await expectStatus(400, 'owner', route, {
		action: 'remove-member',
		revision: 1,
		userId: actors.owner.id
	});
	await expectStatus(403, 'owner', '/api/auth/organization/remove-member', {
		organizationId: orgId,
		memberIdOrEmail: actors.viewer.id
	});
	await expectStatus(403, 'owner', '/api/auth/organization/leave', { organizationId: orgId });
	await expectStatus(200, 'owner', route, {
		action: 'provision',
		revision: 1,
		recipient: `user:${actors.viewer.id}`,
		publicKey: actors.viewer.pair.publicKey,
		wrappedKey: await wrapTo(
			actors.viewer.pair.publicKey,
			orgKey,
			orgContext(orgId, `user:${actors.viewer.id}`, 1)
		),
		identityBinding: await seal(
			orgKey,
			bytes(actors.viewer.pair.publicKey),
			context('recipient', orgId, `user:${actors.viewer.id}`, 1)
		)
	});
	snapshot = await expectStatus(200, 'owner', route);
	await expectStatus(409, 'owner', route, { ...snapshot, action: 'save', revision: 1 });
	await expectStatus(400, 'owner', route, {
		...snapshot,
		action: 'save',
		folders: [{ ...folders[0], parentId: 'foreign' }]
	});
	await expectStatus(200, 'owner', route, {
		action: 'remove-member',
		revision: snapshot.revision,
		userId: actors.viewer.id
	});
	await expectStatus(403, 'viewer', route);
	snapshot = await expectStatus(200, 'owner', route);
	assert.equal(snapshot.rotationRequired, true);
	await expectStatus(409, 'owner', route, { ...snapshot, action: 'save' });
	orgKey = randomKey();
	folderKey = randomKey();
	const rotated = {
		...snapshot,
		action: 'rotate',
		epoch: 2,
		folders: [
			{ ...folders[0], wrappedKey: await seal(orgKey, randomKey(), folderContext(orgId, root, 2)) },
			{ ...folders[1], wrappedKey: await seal(orgKey, folderKey, folderContext(orgId, folder, 2)) }
		],
		secrets: [
			{
				...secrets[0],
				encryptedValue: await seal(
					folderKey,
					bytes('test-secret-only'),
					secretContext(orgId, folder, secret, 'API_KEY', 2)
				)
			}
		],
		envelopes: [
			{
				recipient: ownerRecipient,
				wrappedKey: await wrapTo(
					actors.owner.pair.publicKey,
					orgKey,
					orgContext(orgId, ownerRecipient, 2)
				),
				identityBinding: await seal(
					orgKey,
					bytes(actors.owner.pair.publicKey),
					context('recipient', orgId, ownerRecipient, 2)
				)
			}
		]
	};
	await expectStatus(400, 'owner', route, { ...rotated, secrets: [] });
	await expectStatus(200, 'owner', route, rotated);
	snapshot = await expectStatus(200, 'owner', route);
	assert.equal(snapshot.rotationRequired, false);
	assert.equal(snapshot.epoch, 2);
	const device = await expectStatus(200, null, '/api/auth/device/code', { client_id: 'voe-cli' });
	const devicePair = await identityKeyPair();
	const enrolled = await expectStatus(200, null, '/api/devices', {
		action: 'enroll',
		deviceCode: device.device_code,
		publicKey: devicePair.publicKey
	});
	await expectStatus(200, 'owner', `/api/auth/device?user_code=${device.user_code}`);
	await expectStatus(403, 'owner', '/api/auth/device/approve', { userCode: device.user_code });
	const deviceRecipient = `device:${enrolled.id}`;
	const wrappedKey = await wrapTo(
		devicePair.publicKey,
		orgKey,
		orgContext(orgId, deviceRecipient, 2)
	);
	await expectStatus(200, 'owner', '/api/devices', {
		deviceId: enrolled.id,
		publicKey: devicePair.publicKey,
		envelopes: [
			{
				organizationId: orgId,
				epoch: 2,
				wrappedKey,
				identityBinding: await seal(
					orgKey,
					bytes(devicePair.publicKey),
					context('recipient', orgId, deviceRecipient, 2)
				)
			}
		]
	});
	await expectStatus(200, 'owner', '/api/auth/device/approve', { userCode: device.user_code });
	const issued = await expectStatus(200, null, '/api/auth/device/token', {
		client_id: 'voe-cli',
		device_code: device.device_code,
		grant_type: 'urn:ietf:params:oauth:grant-type:device_code'
	});
	const unusedDevices = await expectStatus(200, 'owner', '/api/devices');
	assert.equal(unusedDevices.find((d: { id: string }) => d.id === enrolled.id).lastUsedAt, null);
	const usedAfter = Date.now();
	const cli = await expectStatus(200, null, route, undefined, issued.access_token);
	const usedDevices = await expectStatus(200, 'owner', '/api/devices');
	const lastUsed = usedDevices.find((d: { id: string }) => d.id === enrolled.id).lastUsedAt;
	assert.ok(Date.parse(lastUsed) >= usedAfter && Date.parse(lastUsed) <= Date.now());
	const browserSnapshot = await expectStatus(200, 'owner', route);
	assert.equal(
		browserSnapshot.devices.find((d: { id: string }) => d.id === enrolled.id).lastUsedAt,
		lastUsed
	);
	const [afterBrowser] =
		await sql`select last_used_at from encryption_device where id=${enrolled.id}`;
	assert.equal(afterBrowser.last_used_at.toISOString(), lastUsed);
	assert.equal(cli.envelopes[0].recipient, deviceRecipient);
	const unwrapped = await unwrapFrom(
		devicePair.privateKey,
		cli.envelopes[0].wrappedKey,
		orgContext(orgId, deviceRecipient, 2)
	);
	assert.deepEqual(unwrapped, orgKey);
	await expectStatus(200, 'owner', route, {
		action: 'revoke-device',
		revision: cli.revision,
		deviceId: enrolled.id
	});
	await expectStatus(403, null, route, undefined, issued.access_token);
	const [afterDenied] =
		await sql`select last_used_at from encryption_device where id=${enrolled.id}`;
	assert.equal(afterDenied.last_used_at.toISOString(), lastUsed);

	const invitationId = randomUUID();
	await sql`insert into invitation (id,organization_id,email,role,status,expires_at,inviter_id) values (${invitationId},${orgId},${actors.outsider.id + '@example.test'},'viewer','pending',now()+interval '1 hour',${actors.owner.id})`;
	const wrong = await call('member', '/api/auth/organization/accept-invitation', { invitationId });
	assert.ok(wrong.status >= 400);
	await expectStatus(200, 'outsider', '/api/auth/organization/accept-invitation', { invitationId });
	const replay = await call('outsider', '/api/auth/organization/accept-invitation', {
		invitationId
	});
	assert.ok(replay.status >= 400);
	const expiredId = randomUUID();
	await sql`insert into invitation (id,organization_id,email,role,status,expires_at,inviter_id) values (${expiredId},${orgId},${actors.viewer.id + '@example.test'},'viewer','pending',now()-interval '1 minute',${actors.owner.id})`;
	const expired = await call('viewer', '/api/auth/organization/accept-invitation', {
		invitationId: expiredId
	});
	assert.ok(expired.status >= 400);
	const signing = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
	const jwk = signing.publicKey.export({ format: 'jwk' });
	const credentialId = Buffer.from(randomUUID()).toString('base64url');
	const cose = Buffer.concat([
		Buffer.from([0xa5, 1, 2, 3, 0x26, 0x20, 1, 0x21, 0x58, 0x20]),
		Buffer.from(jwk.x!, 'base64url'),
		Buffer.from([0x22, 0x58, 0x20]),
		Buffer.from(jwk.y!, 'base64url')
	]);
	await sql`insert into passkey (id,public_key,user_id,credential_id,counter,device_type,backed_up) values (${randomUUID()},${cose.toString('base64')},${actors.owner.id},${credentialId},0,'singleDevice',false)`;
	await sql`insert into account_key_envelope (credential_id,user_id,wrapped_key) values (${credentialId},${actors.owner.id},'test envelope')`;
	for (const uv of [false, true]) {
		const optionsResponse = await fetch(base + '/api/auth/passkey/generate-authenticate-options');
		const options = await optionsResponse.json();
		assert.equal(options.userVerification, 'required');
		const cookies = optionsResponse.headers
			.getSetCookie()
			.map((s) => s.split(';')[0])
			.join('; ');
		const clientData = Buffer.from(
			JSON.stringify({ type: 'webauthn.get', challenge: options.challenge, origin: base })
		);
		const authData = Buffer.concat([
			createHash('sha256').update('localhost').digest(),
			Buffer.from([uv ? 5 : 1, 0, 0, 0, 1])
		]);
		const signature = sign(
			'sha256',
			Buffer.concat([authData, createHash('sha256').update(clientData).digest()]),
			signing.privateKey
		);
		const verified = await fetch(base + '/api/auth/passkey/verify-authentication', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json', origin: base, cookie: cookies },
			body: JSON.stringify({
				response: {
					id: credentialId,
					rawId: credentialId,
					type: 'public-key',
					response: {
						authenticatorData: authData.toString('base64url'),
						clientDataJSON: clientData.toString('base64url'),
						signature: signature.toString('base64url'),
						userHandle: Buffer.from(actors.owner.id).toString('base64url')
					}
				}
			})
		});
		const value = await verified.json();
		if (!uv) assert.ok(verified.status >= 400);
		else {
			assert.equal(verified.status, 200, JSON.stringify(value));
			const proof =
				await sql`select * from passkey_verification where session_id=${value.session.id}`;
			assert.equal(proof[0].credential_id, credentialId);
		}
	}
	console.log(
		'PASS: invitations reject wrong users, expiry and replay; real signed WebAuthn assertions require UV and record credential verification'
	);

	await actor('recoveree');
	await actor('recovery-admin');
	const recoveryOrg = await expectStatus(200, 'recoveree', '/api/auth/organization/create', {
		name: 'Recovery workspace',
		slug: randomUUID()
	});
	await sql`insert into member (id,organization_id,user_id,role,created_at) values (${randomUUID()},${recoveryOrg.id},${actors['recovery-admin'].id},'admin',now())`;
	const recoveryRoute = `/api/workspaces/${recoveryOrg.id}`,
		recoveryRoot = randomUUID();
	let recoveryOrgKey = randomKey();
	const wrapIdentity = async (name: string, epoch: number) => {
		const recipient = `user:${actors[name].id}`;
		return {
			recipient,
			wrappedKey: await wrapTo(
				actors[name].pair.publicKey,
				recoveryOrgKey,
				orgContext(recoveryOrg.id, recipient, epoch)
			),
			identityBinding: await seal(
				recoveryOrgKey,
				bytes(actors[name].pair.publicKey),
				context('recipient', recoveryOrg.id, recipient, epoch)
			)
		};
	};
	await expectStatus(200, 'recoveree', recoveryRoute, {
		action: 'initialize',
		revision: 0,
		epoch: 1,
		folders: [
			{
				id: recoveryRoot,
				name: '',
				parentId: null,
				wrappedKey: await seal(
					recoveryOrgKey,
					randomKey(),
					folderContext(recoveryOrg.id, recoveryRoot, 1)
				)
			}
		],
		secrets: [],
		envelopes: [await wrapIdentity('recoveree', 1)]
	});
	await expectStatus(200, 'recoveree', recoveryRoute, {
		action: 'provision',
		revision: 1,
		publicKey: actors['recovery-admin'].pair.publicKey,
		...(await wrapIdentity('recovery-admin', 1))
	});
	await expectStatus(200, 'recoveree', '/api/identity', { action: 'reset', confirm: 'RESET' });
	assert.equal((await expectStatus(200, 'recoveree', '/api/identity')).identity, null);
	let recoverySnapshot = await expectStatus(200, 'recovery-admin', recoveryRoute);
	assert.equal(recoverySnapshot.rotationRequired, true);
	assert.deepEqual(recoverySnapshot.recipients, [`user:${actors['recovery-admin'].id}`]);
	recoveryOrgKey = randomKey();
	await expectStatus(200, 'recovery-admin', recoveryRoute, {
		action: 'rotate',
		revision: recoverySnapshot.revision,
		epoch: 2,
		folders: [
			{
				id: recoveryRoot,
				name: '',
				parentId: null,
				wrappedKey: await seal(
					recoveryOrgKey,
					randomKey(),
					folderContext(recoveryOrg.id, recoveryRoot, 2)
				)
			}
		],
		secrets: [],
		envelopes: [await wrapIdentity('recovery-admin', 2)]
	});
	const replacement = await identityKeyPair();
	actors.recoveree.pair = replacement;
	await sql`insert into encryption_identity (user_id,public_key,encrypted_private_key,recovery_envelope,recovery_auth_hash) values (${actors.recoveree.id},${replacement.publicKey},'test','test',${'0'.repeat(64)})`;
	await sql`insert into passkey_verification (session_id,recovery) values (${actors.recoveree.session},true)`;
	recoverySnapshot = await expectStatus(200, 'recovery-admin', recoveryRoute);
	await expectStatus(403, 'recoveree', recoveryRoute, {
		action: 'role',
		revision: recoverySnapshot.revision,
		userId: actors['recovery-admin'].id,
		role: 'viewer'
	});
	await expectStatus(200, 'recovery-admin', recoveryRoute, {
		action: 'provision',
		revision: recoverySnapshot.revision,
		publicKey: replacement.publicKey,
		...(await wrapIdentity('recoveree', 2))
	});
	const restored = await expectStatus(200, 'recoveree', recoveryRoute);
	assert.equal(restored.envelopes.length, 1);
	assert.deepEqual(
		await unwrapFrom(
			replacement.privateKey,
			restored.envelopes[0].wrappedKey,
			orgContext(recoveryOrg.id, `user:${actors.recoveree.id}`, 2)
		),
		recoveryOrgKey
	);
	console.log(
		'PASS: admin-assisted identity reset requires surviving key holders and blocks ownership actions until fresh key approval'
	);
	console.log(
		'PASS: organization isolation, role matrix, ownership, provisioning, stale writes, complete rotation, CLI binding, and immediate device revocation'
	);
} finally {
	await sql.end();
}
