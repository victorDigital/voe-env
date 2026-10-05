# VOE ENV

Set `BETTER_AUTH_URL`, `BETTER_AUTH_SECRET`, `EMAIL_API_KEY` (Resend), and `EMAIL_FROM` (verified sender) in your deployment environment or a root `.env` file, then start the web app and its PostgreSQL database:

```sh
docker compose up -d --build
```

Open http://localhost:3000. Sign in by passkey or email setup link. Vault unlock requires a PRF-capable passkey and an offline recovery backup. No `DATABASE_URL` is needed for Compose.

For a hosted deployment, set `BETTER_AUTH_URL` to the public HTTPS URL before building. Compose passes it to SvelteKit for the site's origin. `PUBLIC_BETTER_AUTH_URL` is optional; leave it empty to use the browser's current origin. Rebuild the web image after changing either URL.

The database container generates its password on first startup and keeps it across restarts. PostgreSQL runs on the internal Compose network, and the web app applies migrations after the database is ready.

The `postgres-data` volume stores the database and `db-password` stores its password. Include both volumes in backups.

See [CLI installation and commands](cli/README.md).

Create a workspace, add folders and secrets, and invite members from workspace settings. CLI access is approved in the browser and can be revoked in account settings. See [web setup, encryption, and verification](web/README.md).
