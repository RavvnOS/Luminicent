# Luminicent CLI

Luminicent CLI is a standalone Go-based command line interface for the existing Luminicent deployment workflow. The CLI is intentionally isolated from the backend and frontend while acting as a client to the current Node.js/Express backend.

## API client architecture

The CLI client lives under `internal/api` and communicates with the existing backend at the HTTP routes actually defined in the Node service.

### Backend endpoints currently discovered

- `GET /api/health`
- `POST /api/upload`
- `POST /api/cleanup`
- `GET /api/github/login`
- `GET /api/github/callback`
- `GET /api/github/user`
- `GET /api/github/repos`
- `GET /api/github/branches`
- `POST /api/github/deploy`
- `GET /api/github/deployments`
- `GET /api/github/deployments/:sessionId`
- `POST /api/github/logout`

### Authentication expectations

The current backend uses session-based GitHub authentication via cookies (`express-session`), not a CLI-specific bearer token flow. The API client supports a configurable session cookie when the user authenticates in the browser or a custom backend session is available.

### Current limitations

- Deployment status and live logs are emitted over Socket.IO events (`status`, `terminal_output`, `production-report`), not a REST endpoint.
- There is no dedicated `GET /api/analyze` route in the current backend. Production readiness analysis is returned in the deployment report with the upload/deploy flow.
- The CLI API layer is intentionally reusable and not yet wired into each Cobra command.

## Backend URL configuration

The CLI reads the backend URL from the environment variable `LUMINICENT_API_URL` and defaults to `http://localhost:5000` when unset.

```bash
export LUMINICENT_API_URL=http://localhost:5000
```

Optional session cookie support can be supplied via `LUMINICENT_SESSION_COOKIE` when the backend session is already established.

## Prerequisites

- Go 1.22 or newer
- Git
- A running Luminicent backend on `http://localhost:5000` or a reachable equivalent URL

## Install dependencies

```bash
cd cli
go mod tidy
```

## Run locally

```bash
go run . --help
go run . version
go run . deploy
```

## Run tests

```bash
go test ./...
```

## Build for Linux

```bash
$env:GOOS='linux'; $env:GOARCH='amd64'; go build -o luminicent .
```

## Available commands

- `luminicent deploy`
- `luminicent status`
- `luminicent logs`
- `luminicent stop`
- `luminicent cleanup`
- `luminicent analyze`
- `luminicent login`
- `luminicent config`
- `luminicent version`

## Example usage

```bash
go run . --help
go run . version
go run . deploy
go run . status
go run . logs
go run . stop
go run . cleanup
go run . analyze
go run . login
go run . config
```
