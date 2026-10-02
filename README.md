# VOE ENV

Set `BETTER_AUTH_URL`, `BETTER_AUTH_SECRET`, and `PUBLIC_BETTER_AUTH_URL` in your deployment environment or a root `.env` file, then start the web app and its PostgreSQL database:

```sh
docker compose up -d --build
```

Open http://localhost:3000. The existing authentication and CLI release environment variables still apply. No `DATABASE_URL` is needed for Compose.

For a hosted deployment, set `BETTER_AUTH_URL` to the public HTTPS URL before building. Compose passes it to SvelteKit for the site's origin. `PUBLIC_BETTER_AUTH_URL` is optional; leave it empty to use the browser's current origin. Rebuild the web image after changing either URL.

The database container generates its password on first startup and keeps it across restarts. PostgreSQL runs on the internal Compose network, and the web app applies migrations after the database is ready.

The `postgres-data` volume stores the database and `db-password` stores its password. Include both volumes in backups. The existing `db-data` app volume is retained.

This setup creates a separate database. Existing users and vault data from an external production database require a separate import.

See [CLI installation and commands](cli/README.md).
