# 🐳 Luminicent Docker Integration & Deployment Guide

Luminicent is an interactive DevOps Deployment Simulator that ingests user application repositories (uploaded via `.zip` file or GitHub repo link), automatically detects or builds Dockerfiles, runs simulation containers, monitors real-time metrics, and produces production readiness reports.

---

## 🚀 Running Luminicent with Docker Compose

To containerize and launch the entire Luminicent application stack (Frontend UI + Backend API + Docker Orchestrator):

### Prerequisites
1. **Docker Desktop** installed and running on your host machine.
2. Node.js (v18+) if running outside containers.

### Quick Start Command
Create a backend environment file and generate two independent secrets before starting:

```bash
cp backend/.env.example backend/.env
# Run this command twice; paste each output into a different variable in backend/.env.
node -p "require('node:crypto').randomBytes(32).toString('base64url')"
docker compose up --build
```

The command uses Node.js' cryptographically secure random number generator to produce 32 bytes, encoded as canonical base64url. Do not reuse the output between `LUMINICENT_API_TOKEN` and `SESSION_SECRET`, share it, or commit it. Startup validates the encoding and rejects known placeholders and obvious repeated or sequential patterns; configuration validation cannot prove that a value actually came from a secure random generator. Existing values are never rotated automatically.

Access the applications:
- **Frontend Dashboard**: `http://localhost:5173`
- **Backend API**: `http://localhost:5000` (published on loopback only)
- Redis is reachable only on the Compose network; its port is not published to the host.
- Redis AOF data is stored in the Compose-managed `luminicent-redis-data` volume. This local setup is not a backup or production high-availability guarantee.

The browser prompts for `LUMINICENT_API_TOKEN` when starting an upload or GitHub deployment. The CLI reads the same token from its `LUMINICENT_API_TOKEN` environment variable. Do not put this token in source control or expose the backend port beyond a trusted local machine.
The CLI first requests a server-issued session capability from `POST /api/sessions`, then sends it with the unchanged upload response envelope. It requires a Batch 7-compatible backend; older unauthenticated backends do not implement this session endpoint.

### Real Redis persistence integration tests

The regular backend suite uses a Redis contract mock. The separate integration suite connects to a real Redis instance and skips Redis-dependent cases unless `REDIS_INTEGRATION_URL` points to a loopback service. Start its disposable AOF-backed service from the repository root in PowerShell:

```powershell
docker compose -p luminicent-redis-it -f .\backend\docker-compose.redis-integration.yml up -d --wait
$env:REDIS_INTEGRATION_URL = 'redis://127.0.0.1:16379'
npm run test:integration --prefix backend
```

The suite creates unique key prefixes and deletes only keys beneath its own prefix. It covers shared-client ownership, revocation, TTL, concurrent capacity, record isolation and validation, retention, command failure, and startup rejection when Redis cannot be reached. Do not point it at a shared or production Redis service.

To exercise AOF data recovery across a Redis process restart, seed a probe record, stop and restart only this test Compose service (leave its named volume intact), and verify the record:

```powershell
$env:REDIS_RESTART_PROBE = 'seed'
$env:REDIS_RESTART_PREFIX = "luminicent-restart-it-$([guid]::NewGuid().ToString('N'))"
npm run test:integration --prefix backend
# Copy the nonsensitive UUID printed as "Restart recovery probe scan ID".
docker compose -p luminicent-redis-it -f .\backend\docker-compose.redis-integration.yml stop redis
docker compose -p luminicent-redis-it -f .\backend\docker-compose.redis-integration.yml up -d --wait redis
$env:REDIS_RESTART_PROBE = 'verify'
$env:REDIS_RESTART_SCAN_ID = '<UUID printed by the seed step>'
npm run test:integration --prefix backend
Remove-Item Env:REDIS_RESTART_PROBE
Remove-Item Env:REDIS_RESTART_PREFIX
Remove-Item Env:REDIS_RESTART_SCAN_ID
Remove-Item Env:REDIS_INTEGRATION_URL
docker compose -p luminicent-redis-it -f .\backend\docker-compose.redis-integration.yml down -v
```

`down -v` is scoped to the named integration project and removes its disposable test volume; do not substitute the application's Compose project name. Redis AOF defaults to `appendfsync everysec`, so a forced host or power failure may lose recent acknowledged writes. A successful graceful process restart does not prove backup recovery, high availability, or production durability.

---

## ⚙️ Current Runtime Architecture

```
+-----------------------------------------------------------------------+
| HOST MACHINE                                                          |
|                                                                       |
|   +--------------------------+     +-------------------------------+  |
|   | luminicent-frontend      |     | luminicent-backend            |  |
|   | (Nginx on Port 5173)     |---->| (Express/Socket.IO Port 5000)|  |
|   +--------------------------+     +-------------------------------+  |
|                                      No project worker or Docker socket |
|                                      Project scans return HTTP 503      |
+-----------------------------------------------------------------------+
```

---

## 🧪 Production Challenge Testing Workflow

When a user uploads a project `.zip` or connects a GitHub repo:

1. **Extraction & Context Discovery**:
   - Luminicent extracts the project into `uploads/<sessionId>`.
   - Locates target code (`package.json`, `requirements.txt`, etc.).

2. **Dockerfile Resolution (`dockerfileHelper.js`)**:
   - If user project has an existing `Dockerfile`, Luminicent uses it directly to test production specs.
   - If missing, Luminicent generates an optimized multi-stage `Dockerfile` based on project stack (Node, React, Express, Python, Flask).

3. **Container Building & Real-Time Log Streaming (`dockerOrchestrator.js`)**:
   - Builds image using the Docker daemon available to the backend.
   - Streams build logs real-time to frontend over Socket.IO.
   - Starts each target container with a 512 MiB memory limit, no swap, a 0.5 CPU quota, and a 128-process limit.
   - Streams live container performance metrics (CPU %, Memory %, Network I/O).

4. **Production Readiness Analysis (`productionAnalyzer.js`)**:
   Evaluates production challenges:
   - 🔒 **Security**: Non-root `USER` instruction and heuristic secret-like text patterns in project files (not verified secrets).
   - 🩺 **Reliability**: `HEALTHCHECK` instructions, `.env` file handling.
   - ⚡ **Build Efficiency**: `.dockerignore` (`node_modules` exclusion), multi-stage builds, pin version tags (avoiding `:latest`), `npm ci` vs `npm install`.
   - 📦 **Image Size**: Alerts if image size exceeds `700 MB`.

### Report and CLI result semantics

- The upload API retains its `{ success, sessionId, report, message }` envelope. `report.status` remains the production-readiness score label; it does not indicate whether analysis completed.
- `report.scan.status` is `completed` or `partial`; `findingsDetected` and `findingCount` describe the report's `issues`. Each check includes its name, scope, explanation, status, and finding count where applicable. Current statuses are `passed`, `findings`, `failed`, `skipped`, `unsupported`, and `incomplete`; older reports may use `completed` and `not_performed`, which the CLI interprets conservatively.
- The current report contract defines 12 stable check identifiers, including checks that are unsupported or conditionally skipped. The CLI rejects missing, duplicate, or unexpected identifiers and invalid status/schema data; missing scope, explanations, or finding attribution are treated as partial. Older reports that cannot reliably attribute findings are also partial. The UI shows the expected-check denominator and does not count duplicate or unknown records as passed.
- Dependency vulnerability analysis recursively inventories npm `package.json`, `package-lock.json` (lockfile versions 1, 2, and 3), and `npm-shrinkwrap.json` files, including nested projects. A root npm workspace lock is reused only when it contains a link and package record for the declared workspace and the workspace declaration uses a supported exact, `*`, or `**` pattern; workspace manifests are checked against those records. Unsupported workspace patterns fail closed as incomplete rather than being assumed covered. Identical name/version identities across lockfiles are queried once. The inventory is bounded to 10,000 filesystem entries, 32 directory levels, 10 MiB per dependency file, and 50 MiB total dependency-file bytes. It never follows symbolic links, excludes `.git` and `node_modules`, and marks coverage partial when symlinks or inventory limits prevent a complete scan.
- Nested Go (`go.mod`/`go.sum`), Rust (`Cargo.toml`/`Cargo.lock`), Python (`requirements*.txt`, `Pipfile*`, `pyproject.toml`, `poetry.lock`, `setup.py`, `setup.cfg`), Maven (`pom.xml`), Gradle (`build.gradle[.kts]`, `gradle.lockfile`), Ruby (`Gemfile*`), and PHP (`composer.json`/`composer.lock`) manifests are detected but not vulnerability-analyzed. If they coexist with npm, dependency coverage is partial; without npm coverage, the dependency check is unsupported. Missing npm locks, malformed manifests/locks, symlinks, or inventory limits cannot produce a clean completed dependency result.
- Advisory matching uses the maintained OSV.dev API and its upstream advisory feeds; Luminicent refreshes by querying OSV on each scan and runs no separate local database update job. The backend needs outbound HTTPS access to `api.osv.dev`; unavailable access produces partial results, with no cached-data fallback. Each query sends only the package name, the `npm` ecosystem identifier, and exact locked version. It does not send source files, manifests, paths, or credentials. Package names and versions may themselves disclose private dependency metadata; set `LUMINICENT_OSV_API_ENABLED=false` to opt out when that disclosure is unacceptable. An opt-out with dependencies present marks the check failed and the overall scan partial, never clean; an unset value enables queries and only exact `true` enables an explicitly configured value.
- OSV is queried during each scan; there is no local advisory cache. Lockfiles are capped at 10 MiB, unique locked package versions at 1,000, query batches at 100 packages, advisories at 500, and each API response at 5 MiB. Requests time out after 10 seconds and the full analysis has a 30-second deadline. OSV does not expose a database-wide freshness timestamp; each reported advisory includes its `modified` timestamp, while upstream freshness remains unknown. Vulnerable-version matching is delegated to OSV's version/range matching. A match is not proof of exploitability. A fixed version is shown only when OSV supplies one; otherwise the report recommends reviewing the advisory and selecting a verified unaffected version. Unsupported source severity is reported as `Unknown`, not guessed.
- Dependency analysis is `passed` or `findings` only after a supported lockfile is parsed and all required OSV queries return valid, complete results. A matched vulnerable package produces a finding. Mixed supported and unsupported ecosystems are `incomplete`; missing npm lockfiles when `package.json` exists, malformed or oversized lockfiles/responses, unknown or non-semver versions, manifest/lockfile disagreement, timeouts, network errors, and result limits are `failed` or `incomplete`. If no supported dependency manifest exists, dependency coverage is `unsupported`. Each of these outcomes makes the overall scan partial.
- OWASP Top 10 coverage, dynamic vulnerability testing, and exploit verification remain `unsupported`. A finding-free report means only that checks actually performed emitted no findings within their stated scopes; the heuristic secret-pattern scan does not verify whether a match is a live credential. No score or scan status establishes that the application is secure or production-ready.
- The CLI returns `0` only for a complete report with no findings, `2` when findings are present (including a partial report that also contains findings), and `1` for a finding-free partial result or an execution/report error. Since unsupported checks are explicitly reported, finding-free scans are normally partial until those checks are implemented.
- Backend tests use mocked Docker and OSV calls for deterministic unit coverage, including check aggregation, unsupported and malformed coverage, and secret/failure redaction. These tests do not run dynamic vulnerability tests, verify exploitability, establish external TLS termination, or call live OAuth providers. The local proxy/session test exercises in-process HTTP components only; it is not an external network or production-proxy deployment test.
- The analyzer's secret-pattern pass is bounded to 10,000 files, 10 MiB per file, 100 MiB total file contents, and 32 directory levels. Dockerfile and `.dockerignore` reads are capped at 1 MiB each. Exceeding a limit marks that check failed and the overall scan partial; it does not produce a clean result. Docker metadata calls and daemon connectivity checks have a 10-second wait limit. These waits do not guarantee cancellation of an already-issued Docker API request, and synchronous file operations cannot be preempted while executing.
- The CLI archive creator applies the backend-compatible ceilings before upload: 100 MiB compressed, 1 GiB expanded, 10,000 ZIP entries, 100 MiB per file, and 32 path components. Lower positive per-scan limits can be configured programmatically; limits above the backend caps are rejected. Sensitive paths and symbolic links are excluded or rejected before upload. GitHub repository downloads use the same bounded safe extraction path.

## Isolation boundaries and limitations

- Scan-session capabilities are bound to the verified numeric GitHub identity in the server-side web session. Upload, cleanup, GitHub deployment, deployment-status, and Socket.IO room joins require that identity and the matching capability; owner mismatches are not-found responses. Capability creation, verification, and revocation use Redis and owner checks. A versioned Redis scan-record repository enforces owner-scoped reads and atomic lifecycle transitions, but no current route creates scan records because no scan is dispatched. No scan reports or artifact endpoints are available. The API bearer token is a shared operator credential, not an end-user identity.
- Scan records have a server-generated UUID, bounded source/status fields, monotonic version number, and server-generated timestamps. The allowed states are `queued`, `running`, and terminal `completed`, `failed`, `cancelled`, or `unavailable`; transitions require the expected current state. Records expire after 30 days. Creation always starts in `queued`, never as a successful result.
- Redis is mandatory: missing or unavailable storage prevents backend startup, and persistence-dependent API operations fail closed during outages. Production public deployments require `rediss://`; Compose uses Redis AOF and a named local volume. AOF's default fsync policy and local volume do not establish production durability, backups, or high availability. Redis authentication, network controls, backup, restore, and retention policies remain deployment responsibilities.
- `/api/health` reports `persistenceReady` independently of `scanExecutionAvailable`; persistence readiness does not mean that a worker exists or that scans can be submitted. Redis connection errors are logged by error code only, and the health response does not reveal the Redis endpoint or credentials.
- Project scanning and builds are disabled because no isolated worker, job queue, or authenticated API-to-worker transport is implemented. Uploads in `trusted-local` mode may be size-bounded and safely extracted for archive validation, but they are rejected with HTTP 503 before Docker build, runtime, or project analysis. With `LUMINICENT_EXECUTION_MODE=disabled`, upload requests are rejected before multipart parsing. GitHub deployments are rejected before downloading repository archives. No route has an inline execution fallback.
- Docker Compose sets `LUMINICENT_EXECUTION_MODE=disabled` and does not mount the Docker socket. Access to a Docker socket is effectively privileged control of its host; a normal container sharing the host kernel would not provide the required tenant boundary. The existing Docker orchestrator code is not an isolated worker and must not be enabled as a substitute.
- Upload archive validation remains bounded to 100 MiB compressed, 1 GiB expanded, 10,000 entries, 100 MiB per file, and 32 path components. These limits constrain archive handling only; they do not establish worker resource limits or isolation.
- The `scanWorker` adapter reports an explicit unavailable state. Its strict versioned job and status-message contract is preparatory only: there is no queue, worker dispatch, cancellation, report/artifact persistence, or worker-output validation yet. The scan-record repository does not fabricate records when a session capability or unprocessed request is received.
- A disposable VM or equivalently strong isolation boundary, authenticated job transport, per-job credentials, ownership-aware durable state and artifacts, validated worker output, restricted egress, and enforceable time/memory/CPU/storage/process/file/input limits are required before public multi-tenant scanning. Local unit tests do not validate VM separation, host-kernel separation, network containment, or production deployment.
- The legacy `backend/routes/github.js` module is not mounted by the active server. It is explicitly blocked from handling requests as a defense against accidental future mounting; continue using only the fail-closed `githubRoutes.js` router.
- Local development should bind the backend to `127.0.0.1` (the default) and use HTTP only over loopback. For remote browser access, use this trusted-proxy configuration:

  ```env
  HOST=127.0.0.1
  NODE_ENV=production
  LUMINICENT_TRUSTED_TLS_PROXY=true
  LUMINICENT_LOCAL_ONLY=false
  LUMINICENT_COMPOSE_LOCAL_ONLY=false
  SESSION_SECURE=true
  SESSION_SAME_SITE=none
  FRONTEND_URL=https://app.example.com
  CORS_ORIGIN=https://app.example.com
  GITHUB_CALLBACK_URL=https://api.example.com/api/github/callback
  GITHUB_REDIRECT_URI=https://api.example.com/api/github/callback
  ```

  Keep the backend listener bound to `127.0.0.1` (`http://127.0.0.1:5000`). The TLS-terminating proxy must run on the same host, accept the public browser traffic, overwrite—not append or pass through—`X-Forwarded-Proto` and `X-Forwarded-Host`, and forward backend traffic only to that loopback address. Express trusts forwarded protocol metadata only when the immediate peer is `127.0.0.1` in this explicit mode. This assumes local processes are trusted; loopback trust is not a boundary between mutually untrusted processes on the host. Never expose the backend listener directly on a network interface.

  `FRONTEND_URL` must be a URL origin (no path, query, credentials, or fragment), and that exact HTTPS origin must appear in `CORS_ORIGIN`. `GITHUB_CALLBACK_URL` must be an explicit HTTPS URL on the public proxy route with the `/api/github/callback` or `/auth/github/callback` path; register that exact URL in the GitHub OAuth app. If both callback variables are set, they must be identical. The application rejects invalid or contradictory proxy, cookie, origin, and callback settings at startup. OAuth callback and frontend redirect URLs are never derived from `Host` or forwarded headers. The backend does not terminate TLS or independently verify the external proxy's certificate, TLS policy, or configuration.

  The backend suite includes upload, GitHub-route, and access-control regressions and mocks GitHub's token and user API calls. Its local integration test uses an in-process loopback HTTP proxy to emulate the forwarding contract and verifies secure-cookie issuance plus OAuth session continuity; it does not contact GitHub and does not verify real TLS termination or a production proxy deployment. Direct non-loopback backend binds remain rejected except for the explicit Compose-local-only topology above; direct remote plaintext HTTP is unsupported.
- Do not set `LUMINICENT_EXECUTION_MODE=trusted-local` expecting scans to run: the API still rejects project work because isolated-worker dispatch is unavailable. The execution-mode setting does not provision or configure a worker.
- The API token is a shared operator credential. Session capabilities are stored in the shared Redis service with owner checks and TTL/capacity enforcement. Multi-replica Socket.IO room coordination still requires a shared Socket.IO adapter; Redis-backed capabilities do not provide it.
- On SIGINT/SIGTERM, the backend closes Socket.IO and performs the existing orchestrator shutdown path. Since scan routes do not start Docker work, no uploaded project containers or images should be created by those routes.
- Abrupt termination (crash, forced kill, host restart, or power loss) bypasses this in-process cleanup. The current implementation does not persist Docker resource IDs or attach a durable, deployment-specific ownership marker that can safely distinguish its resources from unrelated Docker workloads. It therefore does not enumerate or delete containers/images at startup; name-based or broad daemon cleanup would be unsafe. Inspect and remove leftovers only through an operator-controlled procedure that verifies ownership against the affected deployment. A dedicated disposable worker/VM and daemon remains the safer recovery boundary.
- Docker's writable container layers and shared build cache have no per-session disk quota in this implementation. Runtime log rotation and the bounded `/tmp` tmpfs do not constrain image layers, build cache, or all daemon storage. Monitor and capacity-plan the Docker data root; do not use automated global prune commands as application cleanup.

---

## 🛠️ Local Development Without Docker Compose

If you want to run the project locally without containers:

1. Start Backend:
   ```bash
   cd backend
   npm install
   npm run dev
   ```

2. Start Frontend:
   ```bash
   cd frontend
   npm install
   npm run dev
   ```
