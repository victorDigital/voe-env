import { defineConfig } from 'drizzle-kit';

// Provide a default for development if DATABASE_URL is not set
const databaseUrl = process.env.DATABASE_URL || 'file:./local.db';

export default defineConfig({
	schema: './src/lib/server/db/schema.ts',
	dialect: 'sqlite',
	dbCredentials: { url: databaseUrl },
	verbose: true,
	strict: true
});
