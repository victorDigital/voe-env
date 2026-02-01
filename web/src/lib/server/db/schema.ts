import { relations } from 'drizzle-orm';
import {
	pgTable,
	text,
	timestamp,
	boolean,
	index,
	integer,
	json,
	unique
} from 'drizzle-orm/pg-core';

export const user = pgTable('user', {
	id: text('id').primaryKey(),
	name: text('name').notNull(),
	email: text('email').notNull().unique(),
	emailVerified: boolean('email_verified').default(false).notNull(),
	image: text('image'),
	publicKey: text('public_key'),
	createdAt: timestamp('created_at').defaultNow().notNull(),
	updatedAt: timestamp('updated_at')
		.defaultNow()
		.$onUpdate(() => /* @__PURE__ */ new Date())
		.notNull()
});

export const session = pgTable(
	'session',
	{
		id: text('id').primaryKey(),
		expiresAt: timestamp('expires_at').notNull(),
		token: text('token').notNull().unique(),
		createdAt: timestamp('created_at').defaultNow().notNull(),
		updatedAt: timestamp('updated_at')
			.$onUpdate(() => /* @__PURE__ */ new Date())
			.notNull(),
		ipAddress: text('ip_address'),
		userAgent: text('user_agent'),
		userId: text('user_id')
			.notNull()
			.references(() => user.id, { onDelete: 'cascade' })
	},
	(table) => [index('session_userId_idx').on(table.userId)]
);

export const account = pgTable(
	'account',
	{
		id: text('id').primaryKey(),
		accountId: text('account_id').notNull(),
		providerId: text('provider_id').notNull(),
		userId: text('user_id')
			.notNull()
			.references(() => user.id, { onDelete: 'cascade' }),
		accessToken: text('access_token'),
		refreshToken: text('refresh_token'),
		idToken: text('id_token'),
		accessTokenExpiresAt: timestamp('access_token_expires_at'),
		refreshTokenExpiresAt: timestamp('refresh_token_expires_at'),
		scope: text('scope'),
		password: text('password'),
		createdAt: timestamp('created_at').defaultNow().notNull(),
		updatedAt: timestamp('updated_at')
			.$onUpdate(() => /* @__PURE__ */ new Date())
			.notNull()
	},
	(table) => [index('account_userId_idx').on(table.userId)]
);

export const verification = pgTable(
	'verification',
	{
		id: text('id').primaryKey(),
		identifier: text('identifier').notNull(),
		value: text('value').notNull(),
		expiresAt: timestamp('expires_at').notNull(),
		createdAt: timestamp('created_at').defaultNow().notNull(),
		updatedAt: timestamp('updated_at')
			.defaultNow()
			.$onUpdate(() => /* @__PURE__ */ new Date())
			.notNull()
	},
	(table) => [index('verification_identifier_idx').on(table.identifier)]
);

export const envVault = pgTable(
	'env_vault',
	{
		id: text('id').primaryKey(),
		userId: text('userId')
			.notNull()
			.references(() => user.id),
		fullKey: text('fullKey').notNull(),
		encryptedValue: text('encryptedValue').notNull(),
		createdAt: timestamp('createdAt').defaultNow().notNull(),
		updatedAt: timestamp('updatedAt')
			.defaultNow()
			.$onUpdate(() => /* @__PURE__ */ new Date())
			.notNull()
	},
	(table) => ({
		userKeyUnique: unique('env_vault_userId_fullKey_unique').on(table.userId, table.fullKey)
	})
);

export const deviceCode = pgTable('deviceCode', {
	id: text('id').primaryKey(),
	deviceCode: text('deviceCode').notNull(),
	userCode: text('userCode').notNull(),
	userId: text('userId').references(() => user.id),
	clientId: text('clientId'),
	scope: text('scope'),
	status: text('status').notNull(),
	expiresAt: timestamp('expiresAt').notNull(),
	lastPolledAt: timestamp('lastPolledAt'),
	pollingInterval: integer('pollingInterval'),
	createdAt: timestamp('createdAt').defaultNow().notNull(),
	updatedAt: timestamp('updatedAt')
		.defaultNow()
		.$onUpdate(() => /* @__PURE__ */ new Date())
		.notNull()
});

export const deviceLog = pgTable('deviceLog', {
	id: text('id').primaryKey(),
	userId: text('userId')
		.notNull()
		.references(() => user.id),
	clientId: text('clientId').notNull(),
	userCode: text('userCode').notNull(),
	scope: text('scope'),
	approvedAt: timestamp('approvedAt').notNull()
});

export const folderShares = pgTable(
	'folder_shares',
	{
		id: text('id').primaryKey(),
		ownerId: text('ownerId')
			.notNull()
			.references(() => user.id, { onDelete: 'cascade' }),
		sharedWithId: text('sharedWithId')
			.notNull()
			.references(() => user.id, { onDelete: 'cascade' }),
		folderPath: text('folderPath').notNull(),
		permission: text('permission').notNull().$type<'read' | 'readwrite'>(),
		encryptedVaultPassword: text('encryptedVaultPassword').notNull(),
		createdAt: timestamp('createdAt').defaultNow().notNull(),
		expiresAt: timestamp('expiresAt')
	},
	(table) => [
		index('folder_shares_ownerId_idx').on(table.ownerId),
		index('folder_shares_sharedWithId_idx').on(table.sharedWithId),
		unique('folder_shares_unique').on(table.ownerId, table.sharedWithId, table.folderPath)
	]
);
