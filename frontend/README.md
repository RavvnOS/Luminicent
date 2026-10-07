# Luminicent Go Frontend

The frontend is a Go `net/http` application. It renders the dashboard with `html/template`, embeds its HTML/CSS/JavaScript with `embed.FS`, and reverse-proxies `/api/` and `/socket.io/` to the backend. The browser uses small vanilla JavaScript handlers and the vendored Socket.IO 4.8.3 client; there is no React or Vite runtime.

## Run locally

From this directory, with the backend available at `http://localhost:5000`:

```powershell
go run .
```

Open `http://localhost:5173`. The server defaults to `HOST=0.0.0.0`, `PORT=5173`, and `BACKEND_URL=http://localhost:5000`. Set those process environment variables to override them. The Go application does not read `.env` files; backend credentials remain exclusively in the backend environment.

To run the full Docker stack from the repository root:

```powershell
docker compose up --build
```

The Go container listens on port 8080 and Compose publishes it at `http://localhost:5173`. Its `BACKEND_URL` points to the Compose backend service.

## API contract used by the browser

All browser API calls are same-origin and pass through the Go proxy. Session cookies remain owned by the backend; browser requests use same-origin credentials. Error responses are JSON objects with an `error` field.

| Endpoint | Method | Request | Response/use |
| --- | --- | --- | --- |
| `/api/upload` | POST | Multipart fields `file` (ZIP) and `sessionId` | `{success, sessionId, report, message}`; upload limit is 100 MB. |
| `/api/cleanup` | POST | JSON `{sessionId}` | `{success, sessionId, message}`; stops/cleans the selected simulation through the backend. |
| `/api/github/login` | GET | Browser navigation | Backend OAuth redirect; callback returns to the frontend with `github_status` or `github_error`. |
| `/api/github/user` | GET | Backend session cookie | `{id, login, name, avatar_url, html_url, type}`; unauthenticated response is 401. |
| `/api/github/repos?page=1&per_page=100` | GET | Backend session cookie | Array of repositories with `id`, `name`, `full_name`, `private`, `default_branch`, `html_url`, `description`, and `owner.login`. |
| `/api/github/branches?owner=...&repo=...` | GET | Backend session cookie and query values | Array of `{name, protected, default}`. |
| `/api/github/deploy` | POST | JSON `{owner, repo, branch, sessionId}` plus backend session cookie | `{success, sessionId, report, message}`. |
| `/api/github/logout` | POST | Backend session cookie | `{success, message}`; backend clears the session. |

The UI displays the report fields currently returned by the backend: score, status, issues and severity, recommendations, Docker information, runtime information, and project configuration checks. It does not calculate or alter the backend's score.

## Realtime contract

The browser connects through `/socket.io` using Socket.IO and emits `joinSession` with `{sessionId}`. The Go proxy forwards both polling and WebSocket upgrade requests without changing event names or payloads.

| Event | Payload used |
| --- | --- |
| `status` | `{sessionId, timestamp, type, stage, percent, status, message, error}` |
| `terminal_output` | `{sessionId, type, message, timestamp}` |
| `build_log` | `{sessionId, data}` |
| `runtime_log` | `{sessionId, data}` |
| `production-report` | `{sessionId, report}` or a report object |
| `docker_stats` / `CONTAINER_METRICS` | `{sessionId, metrics: {cpuUsage, memoryUsage, memoryLimit, memoryPercent, networkRx, networkTx}}` |

`terminal_output` is the canonical combined build/runtime stream; the separate build/runtime events are also accepted and adjacent duplicate lines are collapsed. Socket disconnects and backend errors are shown in the dashboard.

## Configuration and dependencies

- `HOST`: Go frontend bind address.
- `PORT`: Go frontend listen port.
- `BACKEND_URL`: server-side backend origin used for API and Socket.IO proxying. It must be an absolute `http` or `https` URL without a path. It is not exposed to the browser.
- No Go modules outside the standard library are required.
- `static/vendor/socket.io.min.js` is the existing Socket.IO client bundle, version 4.8.3, with its MIT license alongside it. It is the only vendored browser runtime dependency.

The frontend expects the backend to retain the documented HTTP routes, session-cookie behavior, Socket.IO path `/socket.io`, `joinSession` event, and event payloads. No Docker control or analysis logic runs in the frontend.