# Luminicent
1. What is Luminicent?
Luminicent is a project deployment-simulation and security-testing platform under development. Its goal is to help developers evaluate a software project before deploying it by inspecting its configuration and dependencies, checking for selected security issues, and—once a secure execution architecture exists—building and running it in an isolated environment.

Luminicent is planned as a combination of:
- Web application for project submission, scan status, findings, and reports.
- Go-based Linux CLI for command-line workflows.
- Backend services for authentication, project/scan management, analysis, and persistence.
- Isolated execution workers (planned) for builds and runtime tests without exposing the host to untrusted project code.
Luminicent is not yet a complete deployment or security-scanning pipeline. Execution is intentionally disabled while the isolated-worker boundary is unfinished.
2. What are we developing?
The intended workflow is:
1. Acquire a project from an allowed local/archive or Git-based source.
2. Validate inputs and record an authenticated owner's access to the project.
3. Inspect supported project files and dependency lockfiles.
4. Run static configuration, dependency, production-readiness, and selected security checks.
5. When a validated isolation system is available, build and run the project in a disposable, resource-limited environment.
6. Run runtime and dynamic security tests.
7. Collect reproducible findings and supporting evidence.
8. Produce a clear security/readiness report with explicit coverage and skipped/unsupported checks.
9. Support the workflow end to end through the web application and Go CLI.
The current implementation is focused on secure foundations and analysis, not executing uploaded projects. Upload and GitHub deployment routes remain fail-closed until a real isolated-worker design is implemented and tested.
3. Stages completed so far
The project roadmap is tracked in stages below. “Completed” here means implementation groundwork has been reported in the current development branch; it does not mean the full end-to-end product or production security has been verified.
Implemented groundwork
- Stage 1 — Go Linux CLI foundation: CLI and scanner-related code and tests exist.
- Stage 2 — Project acquisition groundwork: local/archive handling and GitHub authentication/integration foundations exist. Actual deployment/execution remains disabled.
- Stage 5 — Production-readiness analysis (partial): checks for selected project and configuration concerns have been added.
- Stage 6 — Static security analysis (partial): selected checks cover hardcoded-credential indicators, private-key material with redacted evidence, TLS verification settings, non-loopback HTTP endpoints in relevant settings, wildcard CORS, and debug-mode configuration when production intent is declared.
- Dependency analysis (partial): supported npm lockfile formats are inspected and dependency versions are matched against OSV advisory data. Other ecosystems and complete live advisory coverage are not established.
- Coverage reporting foundations: statuses such as passed, findings, failed, skipped, unsupported, and incomplete distinguish results from checks that did not complete.
- Input and archive hardening: bounded archive extraction and filesystem traversal protections have been added.
- Authentication and ownership foundations: session capabilities are associated with a server-verified GitHub identity, with owner-scoped access checks.
- Persistence foundations: Redis-backed capability and scan-record storage, expiry, revocation, validation, and retention logic have been added.
- Regression and integration-test groundwork: backend tests and a separate real-Redis integration suite exist.
These are partial stage outcomes, not claims that all planned functionality in those stages is complete. See DOCKER_GUIDE.md and the tests for implementation details.
4. Stages still left to complete
The following roadmap describes the remaining work. Some stages have partial groundwork, but their full goals are still outstanding.
- [ ] Stage 2 — Finish target acquisition: complete and validate supported local/Git workflows and safe project handoff.
- [ ] Stage 3 — Docker isolation and sandbox: implement and validate a real isolated execution boundary, resource limits, network/egress policy, cleanup, and failure handling. A container alone must not be treated as a sufficient security boundary for hostile builds without a validated threat model.
- [ ] Stage 4 — Target deployment and runtime testing: build and run projects only inside the isolated worker; capture logs, exit status, health checks, and timeouts.
- [ ] Stage 5 — Complete production-readiness testing: broaden checks, validate results, and report coverage accurately.
- [ ] Stage 6 — Expand OWASP-oriented security testing: broaden and validate coverage; the existing selected static checks are not complete OWASP Top 10 coverage.
- [ ] Stage 7 — Dynamic vulnerability testing: add safe, bounded runtime tests and clearly distinguish verified findings from indicators.
- [ ] Stage 8 — Finding and evidence collection: persist structured findings and bounded, redacted, reproducible evidence.
- [ ] Stage 9 — Security report generation: generate useful project reports with severity, evidence, limitations, and coverage.
- [ ] Stage 10 — End-to-end Luminicent pipeline: connect acquisition, analysis, isolated execution, findings, persistence, and reports into a tested workflow across the web app and CLI.
- [ ] Stage 11 — Linux hardening and release: perform deployment hardening, operational testing, documentation, recovery testing, and release validation.
- [ ] Persistence verification: run the real-Redis integration tests, including AOF restart/recovery checks, against a working Redis service.
- [ ] Worker/job architecture: implement a real queue/worker transport, durable job lifecycle, owner-scoped result access, cancellation and cleanup, and enforceable resource/egress limits.
5. Current security and execution status
Project execution is disabled by default and must remain disabled until the isolated-worker architecture is implemented and validated.
- Upload and GitHub deployment routes currently fail closed rather than building or running submitted projects.
- No real isolated worker or disposable VM boundary has been established.
- A persisted scan-record model does not mean scans are being executed or that reports are available.
- The real-Redis integration and AOF restart/recovery scenarios have not yet been confirmed against a live Redis service in the latest reported validation.
- Redis persistence is not, by itself, a backup, high-availability, or production-recovery solution.
- Existing static checks cover selected patterns only. A clean result is not proof that a project is secure.
- Do not expose the current application as a public multi-tenant scanning service.
6. Repository structure
- backend/ — Node.js/Express API, authentication/session handling, access control, Redis persistence, routes, and tests.
- frontend/ — web user interface.
- cli/ — Go-based command-line client and scanner-related code.
- docker-compose.yml — local application services.
- DOCKER_GUIDE.md — Docker setup, persistence, and security notes.
7. Development and validation
Use the versions and environment variables specified in the repository's current configuration files. Do not commit .env files, OAuth secrets, session secrets, Redis credentials, or tokens.
Backend tests
npm test --prefix backend
Frontend production build
npm run build --prefix frontend
Go CLI tests and static checks
cd cli
go test -count=1 ./...
go vet ./...
Real Redis integration tests
On a machine with a working Docker daemon, start the dedicated integration Redis service and run the integration suite as described in DOCKER_GUIDE.md. The real-service tests must pass before Redis restart/recovery behavior is considered verified.
8. Project status at a glance
Area	Current status
Go CLI foundation	Implemented groundwork
Static security checks	Partial
Dependency analysis	Partial; supported npm lockfiles
Production-readiness analysis	Partial
Authentication and owner-scoped capabilities	Foundation implemented
Redis-backed persistence	Implemented groundwork; live integration/recovery still needs verification
Upload/GitHub execution	Disabled; routes fail closed
Isolated worker and sandbox	Not implemented/validated
Dynamic testing	Not implemented as a complete workflow
Evidence and report pipeline	Incomplete
End-to-end scan workflow	Incomplete
Production release hardening	Remaining


9. Contribution guidance
Before adding execution functionality, preserve the fail-closed behavior and design the worker boundary, ownership model, resource limits, network policy, cleanup, and evidence handling together. Add tests for failure paths as well as successful cases, and update this README when a stage is implemented and validated.
10. License
Add the project's chosen license and license file before publishing if one has not already been selected.