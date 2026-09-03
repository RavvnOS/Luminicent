# Luminicent

Luminicent is a DevOps deployment simulator that supports uploading zip archives and deploying GitHub repositories using Dockerized app analysis and container simulation.

## Running Luminicent as a Public Website Using Cloudflare Tunnel

This project is meant to run on your own Windows PC, with a public HTTPS URL provided by Cloudflare Tunnel.

The recommended architecture is:

```text
Internet
  |
  v
Cloudflare Tunnel
  |
  v
Your Windows PC
  |
  +--> Luminicent Frontend (public hostname)
  |
  +--> Luminicent Backend (same public hostname via /api)
  |
  +--> Redis
  |
  +--> Docker deployment pipeline
```

The frontend and backend can be exposed through the same public hostname, which is preferred because it avoids cross-origin cookie issues and keeps sessions simple.

### Local vs Public

LOCAL:

```text
http://localhost:5173
http://localhost:5000
```

PUBLIC:

```text
https://luminicent.example.com
```

In the public setup, the browser hits the public HTTPS URL and the tunnel forwards traffic to your local frontend/backend processes. The GitHub OAuth callback must be the public HTTPS backend URL, not localhost.

### 1. Clone and configure the app

```bash
git clone <your-repo>
cd Luminicent-main
```

Create backend/.env using the example values:

```env
HOST=0.0.0.0
PORT=5000
NODE_ENV=production
FRONTEND_URL=https://luminicent.example.com
CORS_ORIGIN=https://luminicent.example.com
SESSION_SECRET=replace-with-a-long-random-secret
SESSION_COOKIE_NAME=luminicent_session
SESSION_TTL_SECONDS=86400
SESSION_SECURE=true
SESSION_SAME_SITE=none
REDIS_URL=redis://localhost:6379
GITHUB_CLIENT_ID=your_github_client_id_here
GITHUB_CLIENT_SECRET=your_github_client_secret_here
GITHUB_CALLBACK_URL=https://luminicent.example.com/api/github/callback
GITHUB_REDIRECT_URI=https://luminicent.example.com/api/github/callback
```

For local development, keep the localhost URL values in backend/.env.example and use the local callback URL.

### 2. Start Redis locally

```bash
docker run -d --name luminicent-redis -p 6379:6379 redis:7-alpine
```

If you want the full local stack in Docker Compose, use the project-level docker-compose file.

### 3. Start the backend

```bash
cd Luminicent-main/backend
npm install
npm run dev
```

The backend should listen on 0.0.0.0 and expose a health endpoint:

```bash
curl http://localhost:5000/api/health
```

Expected response:

```json
{"ok":true,"status":"healthy","timestamp":"..."}
```

### 4. Start the frontend

For a same-origin public deployment, keep the frontend served from the public hostname and set the frontend API URL to the same origin or leave it empty in production.

Local dev:

```env
VITE_API_URL=http://localhost:5000
```

Public tunnel / same-origin:

```env
VITE_API_URL=
```

Then start the frontend locally:

```bash
cd Luminicent-main/frontend
npm install
npm run dev -- --host 0.0.0.0
```

### 5. Install and start Cloudflare Tunnel

Install cloudflared:

```bash
winget install --id Cloudflare.cloudflared -e
```

Then start a tunnel to the frontend port:

```bash
cloudflared tunnel --url http://localhost:5173
```

This gives you a temporary public HTTPS URL such as:

```text
https://your-random-name.trycloudflare.com
```

For a permanent tunnel, configure Cloudflare Zero Trust and a named tunnel, but the local temporary URL is sufficient for testing and first deployment.

### 6. Configure the GitHub OAuth App

In GitHub Developer Settings -> OAuth Apps, set:

- Homepage URL: https://luminicent.example.com
- Authorization callback URL: https://luminicent.example.com/api/github/callback

For local testing, add the localhost callback separately:

```text
http://localhost:5000/api/github/callback
```

Do not use wildcard callback URLs or insecure HTTP in production.

### 7. Configure the public frontend URL in the app

Set:

```env
FRONTEND_URL=https://luminicent.example.com
CORS_ORIGIN=https://luminicent.example.com
GITHUB_CALLBACK_URL=https://luminicent.example.com/api/github/callback
GITHUB_REDIRECT_URI=https://luminicent.example.com/api/github/callback
```

If the frontend is behind the public hostname and the backend is proxied at /api, then same-origin cookies and API calls are the simplest setup.

### 8. Test the public app from another device

Open the public URL from a phone or another machine:

```text
https://luminicent.example.com
```

Then:

1. Click Continue with GitHub
2. Authenticate with a different GitHub account
3. Verify the repositories shown belong only to that account
4. Select a repo and deploy it
5. Log out and repeat with another account

### 9. Multi-user verification

Test with at least two GitHub accounts:

- User A logs in and sees only User A repos
- User B logs in and sees only User B repos
- Their sessions stay isolated
- Their access tokens remain server-side only

---

## GitHub OAuth Production Setup

### 1. Create the GitHub OAuth App

Go to GitHub Developer Settings -> OAuth Apps -> New OAuth App and configure the app as follows:

- Application name: Luminicent
- Homepage URL: your production frontend URL, such as https://luminicent.example.com
- Authorization callback URL: https://your-backend.example.com/api/github/callback in production
- Local development callback: http://localhost:5000/api/github/callback

If your GitHub OAuth App supports multiple redirect URIs, keep both the local callback and the production callback in the app configuration. If it does not, configure the production callback in the app and keep localhost values only in local development for testing.

Do not use wildcard callback URLs or insecure HTTP for production.

### 2. Required GitHub OAuth permissions

The app requests the minimum required GitHub OAuth scopes:

- repo: required to read repository metadata and archive a selected repository for deployment, including private repositories the user can access.
- read:user: required to identify the authenticated user and load only that user's repositories.

The backend never exposes the GitHub access token or client secret to the frontend.

### 3. Backend environment variables

Create a backend .env file or configure the deployment environment with values like:

```env
HOST=0.0.0.0
PORT=5000
NODE_ENV=production
FRONTEND_URL=https://luminicent.example.com
CORS_ORIGIN=https://luminicent.example.com
SESSION_SECRET=replace-with-a-long-random-secret
SESSION_COOKIE_NAME=luminicent_session
SESSION_TTL_SECONDS=86400
SESSION_SECURE=true
SESSION_SAME_SITE=none
REDIS_URL=redis://redis:6379
GITHUB_CLIENT_ID=your_github_client_id_here
GITHUB_CLIENT_SECRET=your_github_client_secret_here
GITHUB_CALLBACK_URL=https://your-backend.example.com/api/github/callback
GITHUB_REDIRECT_URI=https://your-backend.example.com/api/github/callback
```

For local development, use the values in backend/.env.example and keep localhost endpoints instead of production domains.

### 4. Frontend environment variables

The frontend must use a configured backend URL instead of a hardcoded localhost value:

```env
VITE_API_URL=https://your-backend.example.com
```

If the app is served via the same public hostname and proxied through the frontend on /api, then same-origin usage is preferred and VITE_API_URL can be omitted or left blank.

### 5. CORS configuration

The backend only allows the configured front-end origin via CORS. Requests that rely on cookies must include credentials. The production configuration should avoid wildcard origins and should explicitly allow only the deployment frontend origin.

### 6. Session storage configuration

The application uses a production-safe session system backed by Redis when REDIS_URL is configured. This keeps authenticated GitHub sessions isolated per browser and persists across backend restarts and multiple app instances.

### 7. Render or cloud deployment

This project is intentionally designed to run locally on your own PC behind a tunnel, so Render or other cloud hosting is not required. The same environment variables work in any host, but the application is expected to run locally behind Cloudflare Tunnel.

### 8. Local development

1. Copy backend/.env.example to backend/.env and add a valid GitHub OAuth app.
2. Start the backend:

```bash
cd Luminicent-main/backend
npm install
npm run dev
```

3. Start the frontend:

```bash
cd Luminicent-main/frontend
npm install
npm run dev
```

4. Open the frontend in the browser and click Continue with GitHub.

### 9. Logout behavior

The backend exposes POST /api/github/logout to invalidate the authenticated server-side session and clear the auth cookie. After logout, GitHub user and repo requests should return 401 unless the user logs in again.

### 10. Troubleshooting OAuth errors

Common issues:

- callback mismatch: ensure the GitHub OAuth app callback matches the backend callback exactly
- state mismatch: clear cookies and retry
- invalid client credentials: verify GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET in the backend environment
- expired session: log out and log in again
- rate limiting: wait briefly and retry later
- private repository access denied: the user must have permission to that repo

---

## Local development commands

```bash
cd Luminicent-main/backend
npm install
npm run dev

cd ../frontend
npm install
npm run dev
```

## Docker Compose

```bash
docker compose up --build
```

The backend loads GitHub variables from backend/.env and uses Redis for session persistence. The frontend is served on port 5173 and the backend on port 5000.

## Security review summary

The project enforces the following protections for a public multi-user app:

- OAuth state is generated and validated server-side.
- GitHub access tokens are stored in the authenticated session only on the backend.
- The frontend never receives raw access tokens or the client secret.
- Repository requests are scoped to the authenticated GitHub user session.
- Deploy requests validate ownership and repo access before running the existing Docker pipeline.
- Cookies are configured with HttpOnly, Secure, and SameSite settings appropriate for production.
- CORS only allows the configured front-end origin when credentials are in use.

## Multi-user test plan

### User A

1. Open the production site.
2. Log in with GitHub account A.
3. Confirm only repositories for account A load.
4. Select repository A and deploy it.
5. Log out.

### User B

1. Open the production site.
2. Log in with GitHub account B.
3. Confirm only repositories for account B load.
4. Select repository B and deploy it.
5. Log out.

Verify that User A cannot access User B's session or repositories and vice versa.

Go to GitHub Developer Settings -> OAuth Apps -> New OAuth App and configure the app as follows:

- Application name: Luminicent
- Homepage URL: your production frontend URL, such as https://luminicent.example.com
- Authorization callback URL: https://your-backend.example.com/api/github/callback for production
- Local development callback: http://localhost:5000/api/github/callback

If your GitHub OAuth App supports multiple redirect URIs, keep both the local callback and the production callback in the app configuration. If it does not, configure the production callback in the app and keep localhost values only in local development for testing.

Do not use wildcard callback URLs or insecure HTTP for production.

### 2. Required GitHub OAuth permissions

The app requests the minimum required GitHub OAuth scopes:

- repo: required to read repository metadata and archive a selected repository for deployment, including private repositories the user can access.
- read:user: required to identify the authenticated user and load only that user's repositories.

The backend never exposes the GitHub access token or client secret to the frontend.

### 3. Backend environment variables

Create a backend .env file or configure the deployment environment with values like:

```env
PORT=5000
NODE_ENV=production
FRONTEND_URL=https://luminicent.example.com
CORS_ORIGIN=https://luminicent.example.com
SESSION_SECRET=replace-with-a-long-random-secret
SESSION_COOKIE_NAME=luminicent_session
SESSION_TTL_SECONDS=86400
SESSION_SECURE=true
SESSION_SAME_SITE=none
REDIS_URL=redis://redis:6379
GITHUB_CLIENT_ID=your_github_client_id_here
GITHUB_CLIENT_SECRET=your_github_client_secret_here
GITHUB_CALLBACK_URL=https://your-backend.example.com/api/github/callback
GITHUB_REDIRECT_URI=https://your-backend.example.com/api/github/callback
```

For local development, use the values in backend/.env.example and keep localhost endpoints instead of production domains.

### 4. Frontend environment variables

The frontend must use a configured backend URL instead of a hardcoded localhost value:

```env
VITE_API_URL=https://your-backend.example.com
```

Local development can continue with:

```env
VITE_API_URL=http://localhost:5000
```

### 5. CORS configuration

The backend only allows the configured front-end origin via CORS. Requests that rely on cookies must include credentials. The production configuration should avoid wildcard origins and should explicitly allow only the deployment frontend origin.

Example:

```env
CORS_ORIGIN=https://luminicent-frontend.example.com
```

### 6. Session storage configuration

The application uses a production-safe session system backed by Redis when REDIS_URL is configured. This keeps authenticated GitHub sessions isolated per browser and persists across backend restarts and multiple app instances.

Local development can fall back to the in-process memory store, but production should use Redis in Docker Compose, Render, or another managed Redis service.

### 7. Render or cloud deployment

Set these variables on the backend service:

- FRONTEND_URL
- CORS_ORIGIN
- GITHUB_CLIENT_ID
- GITHUB_CLIENT_SECRET
- GITHUB_CALLBACK_URL
- GITHUB_REDIRECT_URI
- SESSION_SECRET
- SESSION_COOKIE_NAME
- SESSION_SECURE
- SESSION_SAME_SITE
- REDIS_URL

Set this on the frontend service:

- VITE_API_URL

Do not expose the GitHub client secret in frontend environment variables or in the bundle output.

### 8. Local development

1. Copy backend/.env.example to backend/.env and add a valid GitHub OAuth app.
2. Start the backend:

```bash
cd Luminicent-main/backend
npm install
npm run dev
```

3. Start the frontend:

```bash
cd Luminicent-main/frontend
npm install
npm run dev
```

4. Open the frontend in the browser and click Continue with GitHub.

### 9. Logout behavior

The backend exposes POST /api/github/logout to invalidate the authenticated server-side session and clear the auth cookie. After logout, GitHub user and repo requests should return 401 unless the user logs in again.

### 10. Troubleshooting OAuth errors

Common issues:

- callback mismatch: ensure the GitHub OAuth app callback matches the backend callback exactly
- state mismatch: clear cookies and retry
- invalid client credentials: verify GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET in the backend environment
- expired session: log out and log in again
- rate limiting: wait briefly and retry later
- private repository access denied: the user must have permission to that repo

---

## Local development commands

```bash
cd Luminicent-main/backend
npm install
npm run dev

cd ../frontend
npm install
npm run dev
```

## Docker Compose

```bash
docker compose up --build
```

The backend loads GitHub variables from backend/.env and uses Redis for session persistence. The frontend is served on port 5173 and the backend on port 5000.

## Security review summary

The project enforces the following protections for a public multi-user app:

- OAuth state is generated and validated server-side.
- GitHub access tokens are stored in the authenticated session only on the backend.
- The frontend never receives raw access tokens or the client secret.
- Repository requests are scoped to the authenticated GitHub user session.
- Deploy requests validate ownership and repo access before running the existing Docker pipeline.
- Cookies are configured with HttpOnly, Secure, and SameSite settings appropriate for production.
- CORS only allows the configured front-end origin when credentials are in use.

## Multi-user test plan

### User A

1. Open the production site.
2. Log in with GitHub account A.
3. Confirm only repositories for account A load.
4. Select repository A and deploy it.
5. Log out.

### User B

1. Open the production site.
2. Log in with GitHub account B.
3. Confirm only repositories for account B load.
4. Select repository B and deploy it.
5. Log out.

Verify that User A cannot access User B's session or repositories and vice versa.
