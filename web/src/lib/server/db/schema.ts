import { sqliteTable, text, integer, unique } from 'drizzle-orm/sqlite-core';

export const user = sqliteTable('user', {
	id: text('id').primaryKey(),
	name: text('name').notNull(),
	email: text('email').notNull(),
	emailVerified: integer('emailVerified', { mode: 'boolean' }).notNull(),
	image: text('image'),
	createdAt: text('createdAt').notNull(),
	updatedAt: text('updatedAt').notNull()
});

export const session = sqliteTable('session', {
	id: text('id').primaryKey(),
	userId: text('userId')
		.notNull()
		.references(() => user.id),
	token: text('token').notNull(),
	expiresAt: text('expiresAt').notNull(),
	ipAddress: text('ipAddress'),
	userAgent: text('userAgent'),
	createdAt: text('createdAt').notNull(),
	updatedAt: text('updatedAt').notNull()
});

export const account = sqliteTable('account', {
	id: text('id').primaryKey(),
	userId: text('userId')
		.notNull()
		.references(() => user.id),
	accountId: text('accountId').notNull(),
	providerId: text('providerId').notNull(),
	accessToken: text('accessToken'),
	refreshToken: text('refreshToken'),
	accessTokenExpiresAt: text('accessTokenExpiresAt'),
	refreshTokenExpiresAt: text('refreshTokenExpiresAt'),
	scope: text('scope'),
	idToken: text('idToken'),
	password: text('password'),
	createdAt: text('createdAt').notNull(),
	updatedAt: text('updatedAt').notNull()
});

export const verification = sqliteTable('verification', {
	id: text('id').primaryKey(),
	identifier: text('identifier').notNull(),
	value: text('value').notNull(),
	expiresAt: text('expiresAt').notNull(),
	createdAt: text('createdAt').notNull(),
	updatedAt: text('updatedAt').notNull()
});

export const envVault = sqliteTable(
	'env_vault',
	{
		id: text('id').primaryKey(),
		userId: text('userId')
			.notNull()
			.references(() => user.id),
		fullKey: text('fullKey').notNull(),
		encryptedValue: text('encryptedValue').notNull(),
		createdAt: text('createdAt').notNull(),
		updatedAt: text('updatedAt').notNull()
	},
	(table) => ({
		userKeyUnique: unique().on(table.userId, table.fullKey)
	})
);

export const deviceCode = sqliteTable('deviceCode', {
	id: text('id').primaryKey(),
	deviceCode: text('deviceCode').notNull(),
	userCode: text('userCode').notNull(),
	userId: text('userId').references(() => user.id),
	clientId: text('clientId'),
	scope: text('scope'),
	status: text('status').notNull(),
	expiresAt: text('expiresAt').notNull(),
	lastPolledAt: text('lastPolledAt'),
	pollingInterval: integer('pollingInterval'),
	createdAt: text('createdAt').notNull(),
	updatedAt: text('updatedAt').notNull()
});

export const deviceLog = sqliteTable('deviceLog', {
	id: text('id').primaryKey(),
	userId: text('userId')
		.notNull()
		.references(() => user.id),
	clientId: text('clientId').notNull(),
	userCode: text('userCode').notNull(),
	scope: text('scope'),
	approvedAt: text('approvedAt').notNull()
});
