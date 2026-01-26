import { drizzle } from 'drizzle-orm/bun-sqlite';
import * as schema from './schema';

import { Database } from 'bun:sqlite';
import { DATABASE_URL } from '$env/static/private';

export const client = new Database(DATABASE_URL, { create: true });
export const db = drizzle(client, { schema });
