# Nomos Middleware (Go external auth adapter)

This repository contains the Go-based implementation of the `middleware-nomos` (external authorization middleware) for the **Nomos Rules Engine**. 

It is designed to be deployed as an Istio `ext_authz` provider (HTTP-based sidecar or central service) in the hot-path of incoming microservice requests.

## Architecture (Option A: recommended)

```
Client → KrakenD → Envoy (Istio) → middleware-nomos (Go) → nomos-service (Java/Quarkus) → Neo4j
                              ↓                                 ↓
                        Does the hard job:                 Rule store only:
                        • Decode JWT                       • Resolves aud → app → proxy
                        • Match path params                • Returns rules or 403
                        • Evaluate L1/L2                   • Never sees JWT claims
                        • Call enrichment (optional)
                        • Cache rules
```

## Features

1. **High Performance**: Built with Go, guaranteeing extremely fast responses, low CPU utilization, and small memory footprint (ideal for sidecars).
2. **Path Variables Parsing & Extraction**: Matches route path parameters template (e.g. `/{country}/accounts/{msisdn}/balance`) against incoming path and extracts variables (`country`, `msisdn`) automatically.
3. **Decodes JWT**: Decodes standard JSON Web Tokens without expensive signature verification (delegated to gateway or mesh filters).
4. **Caching**: In-memory thread-safe TTL cache for active rules and enrichment endpoint lookups, avoiding excessive database/remote network calls.
5. **Multi-Level Verification**:
   - **Level 1 (Fail-Fast)**: Cross-references path arguments against token claims (e.g., country matching).
   - **Level 2 (Deep Ownership)**: Checks ownership, requesting dynamic enrichment payloads from external APIs if defined by the Nomos service logic.

## Environment Variables

- `PORT`: Server listening port (default: `8080`).
- `NOMOS_SVC_URL`: Upstream Nomos core Quarkus rules engine URL (default: `http://nomos-service.default.svc.cluster.local:8080`).

## How to Build & Run

### Locally

```bash
cd nomos-middleware
go run main.go
```

### Build Binary

```bash
go build -o nomos-middleware main.go
```

## API Endpoint `/check` (called by Envoy/Istio)

### Expected Headers

- `x-target-service`: The logical destination service (e.g. `account-service`).
- `authorization`: The incoming `Bearer <JWT>` token.
- `x-original-uri` / `x-original-path` (sent by Envoy): The original route accessed by the client.
- `x-original-method` (sent by Envoy): The original HTTP method (e.g. `GET`).

### Response Behaviors

- **`200 OK`**: Allowed. Response headers include identity info for downstream services:
  - `X-Nomos-Authorization: Success`
  - `X-Nomos-App-Id: <app-id>`
  - `X-Nomos-Idp: <idp-name>`
- **`403 Forbidden` / `401 Unauthorized`**: Blocked. Response contains details:
  - Header `X-Nomos-Error: <ERROR_CODE>`
  - Header `X-Nomos-Param: <failing-param-name>` (if applicable)
  - JSON Body detailing validation failure reason.
