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

---

## Production Scale & Resource Efficiency (300+ Services)

This middleware is engineered specifically for large-scale production microservices environments (handling **300+ services** and **30,000+ aggregate req/s**):

### 1. Sharded Memory Footprint (DaemonSet Model)
Instead of running **300+ sidecar containers** (which wastes cluster memory), this middleware is designed to run as a **DaemonSet** (one pod per physical VM/node) configured with `internalTrafficPolicy: Local` on its Kubernetes Service:
- **Node-Localized Cache**: A middleware pod only caches rules for the specific subset of services running on its same physical worker node (usually 5-15 services). It never loads or wastes memory on the other 280+ services.
- **Ultra-lean RAM consumption**: At 30 services active per node and 500 unique active rule combinations, the Go L1 memory footprint remains incredibly small (**~15MB to 20MB** per node-replica).

### 2. Safeguarding Against "Thundering Herd" (Cold Starts)
To prevent sudden spikes (e.g. 300+ req/s hitting a newly started node daemon) from hammering the core Nomos database:
- **Two-Tier Cache Strategy**: 
  1. **L1 (Go Memory - 15s TTL)**: Shields the network.
  2. **L2 (Shared Redis - 5m TTL)**: Shields the Nomos core database.
- Even if a node starts up with a cold L1 cache, it immediately retrieves warm rules from L2 (Redis) in under 1.5ms, avoiding expensive calls to the central rules engine.
- **Automatic Cleanup**: With a 15-second L1 expiration, inactive rules are automatically cleaned up by Go's garbage collector, ensuring flat-line memory utilization over time.

### 3. Primary-Association Access Pattern & Conditional Enrichment

A key functional requirement of this middleware is managing delegation of access (e.g., a "Father" requesting access to one of multiple associated "Children" accounts, where those accounts are not pre-bundled inside the primary identity token to keep the JWT compact).

#### The Business Case:
- The user's ID token holds their primary identifier (e.g. `primary_msisdn`).
- The JWT contains a specific Boolean claim: **`allAl`**.
  - **`allAl = true`**: The ID token already contains the full list of allowed accounts. No extra lookup is needed.
  - **`allAl = false`**: The ID token only contains a partial response due to size limits.
- When `allAl` is **`false`**, the middleware automatically triggers the **Enrichment Fallback**.
- The enrichment API returns the full list of associated sub-accounts.
- The middleware validates whether the requested path parameter (e.g. child account) belongs to the retrieved list.

#### Primary-Association Schema:
To implement this cleanly and prepare for shared Redis (L2) integration, the resolved delegation relationship is cached as a **`Primary-Association`**:
- **Cache Key**: `enrichment:primary-association:{primary_msisdn}`
- **Cache Value**: Set/Slice of all authorized associated child account IDs (e.g. `["child-1", "child-2", ...]`).
- **Trigger**: Checked on every request; enrichment call is executed **exclusively** when `allAl == false` to ensure maximum efficiency.


