# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ILM CSC API - a Spring Boot 4 REST API implementing the [Cloud Signature Consortium (CSC)](https://cloudsignatureconsortium.org) standard for remote digital signature operations. It integrates with **SignServer** for signature creation, **EJBCA** for certificate authority operations, and an **Identity Provider** (Keycloak) for OAuth2/OIDC authentication.

## Build & Test Commands

```bash
mvn clean package              # Full build with tests and JaCoCo coverage report
mvn test                       # Run unit tests only
mvn test -Dtest=ClassName      # Run a single test class
mvn test -Dtest=ClassName#methodName  # Run a single test method
```

Tests require **Docker** running (TestContainers spins up PostgreSQL, MySQL, Keycloak, Toxiproxy).

Test output is redirected to files (maven-surefire `redirectTestOutputToFile=true`).

**`package` is the gate, not `verify`.** `mvn verify` does not run on a developer
machine: the `spring-boot:start` goal bound to `pre-integration-test` boots the real
application, which needs a deployed `/opt/cscapi` tree (`workers.yml`, `profiles/`,
keystores) plus reachable EJBCA and SignServer endpoints. `sample-config/` does not
supply these. CI (`check_pr.yml`) runs `mvn -B -U package` for the same reason. The
OpenAPI spec under `openapi/` is only produced by `verify` and is not tracked in git.

## Development Environment

```bash
docker-compose -f development/docker-compose.yml up   # Start dev services (PostgreSQL, MySQL, Keycloak, MariaDB)
```

The `dev` Spring profile uses `src/main/resources/application-dev.yml`. In containers, config goes to `/opt/cscapi/application.yml`.

## Architecture

### API Layers

**CSC v2 API** (`csc/v2/`) - Standard CSC endpoints, secured with OAuth2 JWT:
- `POST csc/v2/info` - Service metadata (public)
- `POST csc/v2/credentials/list` and `credentials/info` - Credential queries
- `POST csc/v2/signatures/signHash` - Raw hash signing (plain signatures)
- `POST csc/v2/signatures/signDoc` - Document/digest signing (AdES signatures)

**Management API** (`management/v1/`) - Non-CSC credential lifecycle, secured with mTLS and/or OAuth2:
- `POST management/v1/credentials/{create,remove,disable,enable,rekey}`

### Signing Flow

`SignatureFacade` routes requests to the appropriate signing pipeline:

- **DocumentContentSigning** - Full document signing via SignServer
- **DocumentHashSigning** - Pre-computed digest signing
- **PlainHashSigning** - Raw hash signing (LongTermToken only)

Each pipeline uses a **SignatureProcessTemplate** that orchestrates: Authorization -> Token Provision -> Signing -> Response Mapping.

**Token types** determine key sourcing:
- **LongTermToken** - Persistent credentials stored in database
- **OneTimeToken** - Single-use keys from pre-generated pool
- **SessionToken** - Session-scoped temporary credentials

### External Service Clients

- **SignserverClient** - REST + SOAP/WS. Handles signing, key generation, CSR generation, certificate import
- **EjbcaClient** - SOAP/WS. Handles end entity creation, CSR signing, certificate revocation
- **IdpClient** - REST. Fetches user info, downloads JWKS for JWT validation (retry with exponential backoff)

### Authentication

- **OAuth2 JWT**: `CscJwtAuthenticationConverter` extracts claims including Signature Activation Data (SAD) into `CscAuthenticationToken`
- **mTLS**: Chain of filters (`MtlsClientCertificateFilter` -> `MtlsAuthorizationFilter` -> `MtlsAuthenticationFilter`) validates client certificates against trust anchors, issuer/subject DN allowlists, and fingerprint pinning
- Management auth type is configurable: `oauth2`, `certificate`, or `certificate_oauth2`

### Configuration

YAML-driven configuration at multiple levels:
- `application.yml` - Main Spring Boot config (DB, TLS, IDP, HTTP client settings)
- `workers.yml` (path in `csc.workerConfigurationFile`) - SignServer worker definitions with crypto tokens and capabilities
- `profiles/` directory (path in `csc.profilesConfigurationDirectory`) - Credential profiles and signature qualifier profiles per CA provider
- `key-pool-profiles.yml` - Pre-generated key pool sizes and replenishment schedules

### Database

- **Flyway** migrations in `src/main/resources/db/specific/{postgresql,mysql}/`
- Schema: `csc`, history table: `csc_schema_history`
- Supports PostgreSQL and MySQL
- Database retry: max 3 attempts with exponential backoff for transient SQL errors

### Scheduled Tasks

Background jobs (cron-configurable via `csc.*` properties):
- Pre-generate session keys, one-time keys, and long-term keys
- Clean up expired sessions and used keys
- Concurrency controlled via `csc.concurrency.maxKeyGeneration` / `maxKeyDeletion`

### Key Design Patterns

- **Result monad** (`Result<T, E>`) for functional error handling with `flatMap`/`map`/`mapError`
- **Template Method** in `SignatureProcessTemplate` for signing orchestration
- **Strategy** pattern for signers, authorizers, token providers, and key selectors
- **Repository pattern** for both DB entities and YAML-based config (WorkerRepository, CredentialProfileRepository)

## Package Structure

```
com.otilm.csc
├── api/auth/          # Authentication (JWT converter, mTLS filters, token validation)
├── clients/           # External service clients (signserver/, ejbca/, idp/)
├── common/            # Shared utilities (Result monad, etc.)
├── components/        # Spring components (scheduled tasks, key pool management)
├── configuration/     # Configuration properties and Spring config classes
├── controllers/       # REST controllers (v2/ for CSC, noncsc/v1/ for management)
├── crypto/            # Cryptographic utilities (algorithm mapping, OID handling)
├── model/             # DTOs, request/response objects, domain models
├── providers/         # Certificate authority provider abstraction
├── repository/        # JPA repositories and YAML-based config repositories
├── service/           # Business logic services
└── signing/           # Signing orchestration (facade, pipelines, token providers)
```

## Dependency Management

Renovate (`renovate.json`, `config:recommended`) opens update PRs. Two rules keep the
`pom.xml` sane:

- **Do not pin what the Spring Boot BOM manages, unless you mean to move ahead of it.** `flyway`,
  `snakeyaml`, `commons-lang3`, `httpclient5`, `httpcore5`, `logback`, `jackson` and `tomcat` carry
  no `<version>` and move with the parent. A forward-pin silently becomes a *downgrade* once the BOM
  catches up — `<tomcat.version>` was pinned to 11.0.22 ahead of the BOM and was removed when Spring
  Boot 4.1.0 began managing that exact version.
- **Deliberate forward overrides of BOM-managed versions.** Spring Boot 4.1.0 manages
  `postgresql` 42.7.11, `mysql` 9.7.0 and `testcontainers` 2.0.5; the `version.postgresql`,
  `version.mysql` and `version.testcontainers*` properties override the first two to pick up fixes
  the BOM has not reached yet. Drop an override once the BOM meets or passes it, or it turns into
  the `tomcat.version` problem above.
- **Not BOM-managed at all**, so the `version.*` property is the only source: BouncyCastle, jjwt,
  commons-text, springdoc, spring-retry, Instancio, testcontainers-keycloak, and the JaCoCo plugin.

Notes on specific dependencies:

- **`com.sun.istack:istack-commons-runtime`** is declared explicitly on purpose. `jaxb-runtime`
  (pulled by `spring-boot-starter-web-services` via `spring-ws-core`) uses `FinalArrayList`
  from it but no longer shades it, and the artifact does not reach the *runtime* classpath
  transitively — it resolves at `test` scope only. Without the explicit declaration, SOAP
  marshalling fails at runtime with `NoClassDefFoundError`. Verify with
  `mvn dependency:build-classpath -DincludeScope=runtime` before removing it.
- **TestContainers 2.x renamed every module coordinate** to a `testcontainers-*` prefix
  (`org.testcontainers:postgresql` → `org.testcontainers:testcontainers-postgresql`, and the
  same for `mysql`, `toxiproxy`, `junit-jupiter`). Renovate cannot rename coordinates, so its
  PRs bump only the core `testcontainers` artifact — applying one as-is leaves the modules on
  1.x and breaks resolution. 2.x also stopped shading commons-lang3, so
  `org.testcontainers.shaded.*` imports no longer resolve.
- **`com.mysql:mysql-connector-j` uses calendar versioning** from `26.7.0` onward (it follows
  `9.7.0`). A jump from 9.x to 26.x is expected, not a hijacked coordinate.
- **`com.github.dasniko:testcontainers-keycloak`** hard-couples to a TestContainers major
  version (4.3.x requires 2.0.x), so the two move together.
- **Outbound HTTP defaults are pinned explicitly**, not inherited. In `ServerConfiguration`,
  `getHttpClient` states `HostnameVerificationPolicy.CLIENT` with
  `HttpsSupport.getDefaultHostnameVerifier()`, and `setSoKeepAlive(false)`. httpclient5 5.6 changed
  the single-argument `DefaultClientTlsStrategy` constructor to select
  `HostnameVerificationPolicy.BUILTIN` (JSSE endpoint identification, which rejects certificates
  with no `subjectAltName`), and httpcore5 5.4 changed the `SocketConfig` default for `soKeepAlive`
  to `true`. Both are stated explicitly so a BOM bump cannot silently change how the service
  authenticates EJBCA, SignServer, and IDP endpoints. Deployments using internal CN-only
  certificates depend on this.

Keycloak's `admin-cli` client enables lightweight access tokens by default, and the userinfo
endpoint rejects them. `IdpClientTest` turns that flag off during setup so it receives a full
access token, as a real IDP client would.

## Test Coverage & Sonar

Line coverage is **43.85%** (2682/6116) and instruction coverage 42.81%. This is pre-existing
test debt, concentrated in the signing pipelines, external service clients, and services.
SonarCloud gates on **new-code** coverage, so the ≥80% standard applies to new and changed
code; a change that adds no production lines satisfies it trivially. Raising the overall
figure is separate, deliberate work — do not bundle it into an unrelated change, because it
destroys the "tests unchanged and still green" signal that regression-free refactors rely on.

## Quality Gate Before Pushing

Run locally before opening a PR (GitHub Actions then run the authoritative SonarCloud and
CodeQL checks):

- `mvn clean package` — 564 tests, 0 failures. A changed test count means something was
  silently skipped.
- `./scripts/sonar-local.sh` — ephemeral SonarQube smoke check reporting the quality gate,
  duplication, and issues on changed files. Duplication must stay under 3%. An ephemeral
  server has no new-code baseline, so SonarCloud on the PR is authoritative.
- `copilot --allow-all-tools -p "..."` — an independent review pass on the diff.

Container vulnerability scanning is **not** run locally. The shared reusable workflows in
`OmniTrustILM/.github` (`containers-test.yml`, `containers-build-and-push.yml`) enforce the
org-default Trivy policy. They read a repo-local Trivy config only when
`allow-trivy-config-override: true` is passed, and no csc-api workflow passes it.

## Commits & PRs

Write a plain description of what changed — **no** co-author or attribution trailers, and
**no** validation or quality-status lines (test counts, "BUILD SUCCESS", coverage numbers).
Do not push or open a PR without maintainer approval.
