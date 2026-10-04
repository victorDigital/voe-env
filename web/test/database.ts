export function testDatabaseURL() {
	if (!process.env.DATABASE_URL)
		throw new Error('Set DATABASE_URL for the local test PostgreSQL server');
	const database = new URL(process.env.DATABASE_URL);
	if (!['localhost', '127.0.0.1', '[::1]'].includes(database.hostname))
		throw new Error('Tests only accept local PostgreSQL servers');
	database.pathname = '/voe_passwordless_test';
	return database;
}
