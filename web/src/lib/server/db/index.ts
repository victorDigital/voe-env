import { drizzle } from 'drizzle-orm/postgres-js';
import postgres from 'postgres';
import * as schema from './schema';
import { env } from '$env/dynamic/private';
import { building } from '$app/environment';

if (!env.DATABASE_URL && !building) {
	throw new Error('DATABASE_URL environment variable is required');
}

console.log('[DB] Connecting to PostgreSQL...');

const client = env.DATABASE_URL ? postgres(env.DATABASE_URL) : postgres();
export const db = drizzle(client, { schema });

console.log('[DB] PostgreSQL connection established');
