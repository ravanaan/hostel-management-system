# HostelDesk

HostelDesk is a single-property hostel management app with server-backed administrator sign-in. Student records, room assignments, fee statuses, maintenance tickets, and notices are stored in SQLite on the server. The browser does not load those records until the administrator has authenticated. The starter room directory contains 15 rooms across blocks A, B, and C.

## Run locally on Windows

1. Install Node.js 20 or later.
2. In PowerShell, from this project folder, install dependencies and create the local environment file:

   ```powershell
   npm install
   Copy-Item .env.example .env
   ```

3. Edit `.env` and set a unique administrator username, a strong password of at least 12 characters, and a random session secret of at least 32 characters. Generate a session secret with:

   ```powershell
   node -e "console.log(require('node:crypto').randomBytes(48).toString('hex'))"
   ```

   The initial administrator password is hashed and saved when the database is first created. After that, the stored hash is used for sign-in; keep `.env` private.

4. Start the server and open the local address:

   ```powershell
   npm start
   ```

   Browse to `http://localhost:3000`. Do not open the HTML file directly.

The SQLite database and session store are created in `data\`. Back up that directory securely. The database is intentionally not exposed as a static web file.

## Deployment

Use HTTPS in production and set `NODE_ENV=production` behind a correctly configured HTTPS reverse proxy. Set a fresh `SESSION_SECRET` and unique administrator credentials through the hosting provider's secret manager. Restrict access to the server and database backups; do not commit `.env` or `data\`.

The application currently provisions one administrator on first startup. It does not yet include administrator account recovery or a student-facing portal.

Administrator sessions use an HTTP-only cookie, request-verification tokens, login rate limiting, and a 30-minute inactivity timeout. Sign out when leaving a shared device unattended.
