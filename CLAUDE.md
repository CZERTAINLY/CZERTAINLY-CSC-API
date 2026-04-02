# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

CZERTAINLY CSC API - a Spring Boot 3.5 REST API implementing the [Cloud Signature Consortium (CSC)](https://cloudsignatureconsortium.org) standard for remote digital signature operations. It integrates with **SignServer** for signature creation, **EJBCA** for certificate authority operations, and an **Identity Provider** (Keycloak) for OAuth2/OIDC authentication.

## Build & Test Commands

```bash
mvn clean package              # Full build with tests and JaCoCo coverage report
mvn test                       # Run unit tests only
mvn verify                     # Run tests + integration tests (generates OpenAPI spec)
mvn test -Dtest=ClassName      # Run a single test class
mvn test -Dtest=ClassName#methodName  # Run a single test method
```

Tests require **Docker** running (TestContainers spins up PostgreSQL, MySQL, Keycloak, Toxiproxy).

Test output is redirected to files (maven-surefire `redirectTestOutputToFile=true`).

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
com.czertainly.csc
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
