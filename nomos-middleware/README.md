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

> [!IMPORTANT]
> **Sidecar Pattern Deprecated**: Injecting this middleware as a sidecar container in all 300+ application pods is deprecated due to excessive resource replication and cluster-wide configuration drift.

Instead of running sidecars, this middleware is engineered to run as a **DaemonSet** (exactly one pod per physical VM/worker node) configured with `internalTrafficPolicy: Local` on its Kubernetes Service. 

> [!WARNING]
> **Istio Mesh Routing Caveat**: Because Istio Envoy sidecars bypass Kubernetes `kube-proxy` (iptables), the `internalTrafficPolicy: Local` setting is ignored by default. Envoy will round-robin requests globally across all nodes. 
> To force Envoy to stay node-local, you **must apply an Istio DestinationRule** with hostname-prioritized failover:

```yaml
apiVersion: networking.istio.io/v1beta1
kind: DestinationRule
metadata:
  name: nomos-middleware-local-routing
  namespace: default
spec:
  host: nomos-middleware.default.svc.cluster.local
  trafficPolicy:
    loadBalancer:
      localityLbSetting:
        enabled: true
        failoverPriority:
          - "kubernetes.io/hostname" # Force Envoy to prioritize the SAME host VM node!
```

#### Why DaemonSet is Chosen Over a Centralized Deployment:

| Architectural Metric | Centralized Deployment | Node-Local DaemonSet (Selected) |
| :--- | :--- | :--- |
| **Network Hop & Latency** | **Inter-Node Network Hop**: Traffic travels across VM nodes, adding **2ms to 8ms** round-trip network latency on *every* request. | **Node-Local Loopback**: Traffic stays inside local VM memory routing. Runs at **sub-millisecond (< 1ms)** latency. |
| **Blast Radius & Failure Scope** | **Global Outage**: If the centralized deployment is overloaded or goes down, **all 300+ services** are instantly blocked. | **Node-Isolated**: If a daemon replica on Node A encounters an issue, only Node A is impacted. Nodes B, C, and D remain completely unaffected. |
| **Auto-Scaling Complexity** | **Complex**: Requires scaling via CPU/Memory-based HPAs configured to guess and adapt to aggregate mesh traffic levels. | **Saves Overhead**: Scales out/in automatically with your node infrastructure. Zero HPA tuning required. |
| **RAM Sharding** | **Inefficient**: Replicas load aggregate rules for all services. | **High Efficiency**: A replica only caches rules for the 5-15 services running on its specific worker node (~15MB to 20MB per node). |

---

## How to Validate Node-Local Routing in Production

To verify that Istio is respecting the `DestinationRule` and routing 100% of the authorization traffic locally within the same physical node, use the following validation procedures:

### 1. Inspect Envoy Endpoints via `istioctl`
Run `istioctl proxy-config endpoint` on any active application pod (e.g. `account-service`). You should observe that only the local Node IP is prioritized with active traffic weights:

```bash
# Query active endpoints for the nomos-middleware service from an app container
istioctl proxy-config endpoint <your-app-pod-name> --cluster "outbound|8080||nomos-middleware.default.svc.cluster.local"
```

* **Expected Output**:
  You will see multiple IP addresses (corresponding to your DaemonSet pods on different nodes), but the endpoint with the IP of the **same physical node** will be assigned **100% traffic weight** (or marked as `healthy` and preferred in the local routing table).

### 2. Live Log Analysis (The Empirical Test)
1. Identify two application pods running on different physical nodes:
   - `pod-alpha` on **Node-1**
   - `pod-beta` on **Node-2**
2. Identify the corresponding `nomos-middleware` daemon pods:
   - `middleware-daemon-1` on **Node-1**
   - `middleware-daemon-2` on **Node-2**
3. Tail the logs of both middleware daemons simultaneously:
   ```bash
   kubectl logs -f middleware-daemon-1
   kubectl logs -f middleware-daemon-2
   ```
4. Execute test requests from `pod-alpha` (on Node-1):
   ```bash
   kubectl exec pod-alpha -- curl -H "X-Target-Service: account-service" http://account-service:8080/check
   ```
5. **Validation Verdict**:
   - **Success**: 100% of the request check logs appear on `middleware-daemon-1` (Node-1). Zero logs appear on `middleware-daemon-2` (Node-2).



### 2. TTL Tuning & Caching Philosophy (Production Configuration)

To optimize database and cache operations at scale, different TTL (Time-To-Live) configurations are used for rules and user-relation data:

- **Rules TTL (1 Hour default)**:
  - **Philosophy**: API routing and access control policies (defined in Nomos) are highly stable configurations. They do not change minute-by-minute. 
  - **Benefit**: Setting rules TTL to **1 hour** reduces outbound traffic to your centralized Nomos database to virtually zero (just 1 query per hour per unique proxy-audience).
  - **Instant Eviction**: If an urgent rule change must propagate immediately, a platform administrator can run a zero-downtime rolling restart of the DaemonSet (`kubectl rollout restart ds nomos-middleware`) which clears L1 memory instantly across all nodes.
- **Enrichment TTL (1 to 2 Minutes)**:
  - **Philosophy**: Active user relations (e.g. associated family MSISDNs) are dynamic and session-based.
  - **Benefit**: Keeps user-sensitive relationship maps in node RAM only while the user is actively navigating. It automatically garbage-collects user session records 2 minutes after they leave the application.
- **Two-Tier Cache Strategy (with L2 Redis)**:
  - **L1 (Go Memory - 15-30s TTL)**: Prevents redundant connection pooling spikes.
  - **L2 (Shared Redis - 1 Hour TTL)**: Acts as the warm data store so newly scaled nodes never have to query the central Neo4j database on startup.


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

#### Primary-Association Schema & L1 Enrichment Cache:
To implement this cleanly and prepare for shared Redis (L2) integration, the resolved delegation relationship is cached as a **`Primary-Association`** using a dedicated, short-lived **L1 Enrichment Cache**:
- **Cache Key**: `enrichment:primary-association:{primary_msisdn}` (or `token:endpoint` locally)
- **Cache Value**: The parsed slice/set of all authorized associated child account IDs (e.g. `["child-1", "child-2", ...]`).
- **Trigger**: Checked on every incoming request. The enrichment call is executed **exclusively** when `allAl == false` to ensure maximum efficiency.

#### How the L1 Enrichment Cache solves Parallel Dashboard Requests:
When a user (the "Father") logs in, the dashboard client often fires 8-10 parallel, concurrent requests to get the balance and status of all his associated sub-accounts (the "Children") simultaneously.
1. **Request 1 (Child A)**: Finds no cache. Triggers the outbound enrichment call, fetches the complete list of associated accounts, validates Child A, and **populates the L1 Enrichment Cache**.
2. **Requests 2-8 (Children B to H)**: Arrive milliseconds later. They instantly hit the warm **L1 Enrichment Cache** in under **1 microsecond**, completely avoiding duplicate external network calls.
3. This protects downstream user/profile databases from **8x traffic amplification** during login/dashboard load sequences.




---

## Security Tracing Integration

The file `security_tracing_candidate.go` provides OpenTelemetry-based tracing functions for the authorization flow. Below is the integration reference showing where each function is called inside `handleCheck`:

### Trace Waterfall

```
AuthorizationCheck (root — server span)
 ├── ResolveNomosRules (client span — network or cache)
 ├── MatchRule (internal span)
 ├── EvaluateBOLA/L1/country (internal span)
 ├── AuditDynamicEnrichment (client span — if triggered)
 ├── EvaluateBOLA/L2/msisdn (internal span)
 └── FinalDecision: ALLOW or DENY
```

### Integration in `handleCheck`

```go
func handleCheck(w http.ResponseWriter, r *http.Request) {
    start := time.Now()

    // ─── ROOT SPAN (carries target_service, path, request_id) ───
    ctx, rootSpan := TraceSecurityCheck(r)
    defer rootSpan.End()

    // ... decode JWT ...
    BindClientIdentity(rootSpan, decodedJwt)

    // ─── NOMOS RESOLUTION (measures latency, records cache hit/miss) ───
    resolveStart := time.Now()
    var cacheHit bool
    if cached, found := rulesCache.Get(cacheKey); found {
        rulesData = cached.(*RulesResponse)
        cacheHit = true
    } else {
        rulesData, err = fetchRulesFromNomos(targetService, audience, issuer, originalMethod)
        // ... handle error ...
        rulesCache.Set(cacheKey, rulesData, config.RulesTTL)
    }
    TraceNomosResolution(ctx, targetService, audience, issuer, cacheHit, time.Since(resolveStart), len(rulesData.Rules), err)

    // ─── RULE MATCHING ───
    matchCtx, matchSpan := TraceRuleMatch(ctx, matchedRule.ID, matchedRule.PathPattern, originalPath, len(rulesData.Rules))
    matchSpan.End()

    // ─── LEVEL 1 VALIDATIONS (fail-fast) ───
    for _, val := range matchedRule.Validations {
        if val.Level == 1 {
            violation, bolaSpan := TraceBOLAEvaluation(matchCtx, 1, matchedRule.ID, matchedRule.PathPattern, val.ParamName, claimVal, pathVal, val.Validation)
            bolaSpan.End()
            if violation {
                AuditFinalDecision(rootSpan, false, "L1_MISMATCH", "...")
                EmitSecurityAuditLog(SecurityAuditEntry{Decision: "DENY", ...})
                return
            }
        }
    }

    // ─── LEVEL 2 VALIDATIONS (ownership + optional enrichment) ───
    var enriched bool
    for _, val := range matchedRule.Validations {
        if val.Level == 2 {
            if needsEnrichment {
                enrichStart := time.Now()
                enrichedData, err = callEnrichmentEndpoint(domain, val.Enrichment.Endpoint, token)
                TraceDynamicEnrichment(ctx, val.Enrichment.Endpoint, val.Enrichment.DomainFrom, enrichCacheHit, time.Since(enrichStart), err == nil, err)
                enriched = true
            }
            violation, bolaSpan := TraceBOLAEvaluation(matchCtx, 2, matchedRule.ID, matchedRule.PathPattern, val.ParamName, claimVal, pathVal, val.Validation)
            bolaSpan.End()
            if violation {
                AuditFinalDecision(rootSpan, false, "L2_OWNERSHIP_VERIFICATION_FAILED", "...")
                EmitSecurityAuditLog(SecurityAuditEntry{Decision: "DENY", ...})
                return
            }
        }
    }

    // ─── ALLOW ───
    AuditFinalDecision(rootSpan, true, "", "")

    // ─── STRUCTURED AUDIT LOG (always emitted, works without OTel collector) ───
    EmitSecurityAuditLog(SecurityAuditEntry{
        RequestID:     requestID,
        TargetService: targetService,
        Path:          originalPath,
        Method:        originalMethod,
        Subject:       subject,
        Issuer:        issuer,
        Audience:      audience,
        MatchedRule:   matchedRule.ID,
        RulePattern:   matchedRule.PathPattern,
        Decision:      "ALLOW",
        DurationMs:    time.Since(start).Milliseconds(),
        CacheHit:      cacheHit,
        Enriched:      enriched,
    })
}
```

> **Note:** The latency for the Nomos call is measured with `time.Since(resolveStart)` and recorded as `nomos.resolution_ms` on the `ResolveNomosRules` span. The middleware has no visibility into Neo4j — it only measures the round-trip to the Nomos Quarkus service.

For full details on span attributes, SIEM alerting, and security constraints, see [`SECURITY_FOCUS.md`](./SECURITY_FOCUS.md).

---

## 🔒 Istio Integration: Workload Labeling & AuthorizationPolicy

To enforce external authorization using `nomos-middleware` on microservice requests, you must apply an Istio `AuthorizationPolicy` that targets workloads carrying the label `nomos.security: enabled`.

### 1. Target Service Deployment (Workload) Example
Add the label `nomos.security: enabled` to the Deployment's **Pod template metadata labels**:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: account-service
  namespace: default
spec:
  replicas: 3
  selector:
    matchLabels:
      app: account-service
  template:
    metadata:
      labels:
        app: account-service
        nomos.security: enabled # 👈 Activates external authorization check
    spec:
      containers:
        - name: account-service
          image: your-registry/account-service:latest
          ports:
            - containerPort: 8080
```

### 2. Istio AuthorizationPolicy Example
Define an `AuthorizationPolicy` with action `CUSTOM` targeting the workloads labeled with `nomos.security: enabled`:

```yaml
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: nomos-external-authz
  namespace: default # Scope to the namespace containing your services
spec:
  selector:
    matchLabels:
      nomos.security: enabled # 👈 Selects workloads labeled with this key-value pair
  action: CUSTOM
  provider:
    name: nomos-middleware # 👈 Must match the ExtensionProvider name in MeshConfig
  rules:
    - to:
        - operation:
            ports: ["8080"] # Protects target application HTTP ports
```

### 3. Extension Provider Definition (MeshConfig)
For the `AuthorizationPolicy` above to route checks properly, register the `nomos-middleware` service in Istio's cluster-wide `MeshConfig`:

```yaml
meshConfig:
  extensionProviders:
    - name: "nomos-middleware"
      envoyExtAuthzHttp:
        service: "nomos-middleware.default.svc.cluster.local"
        port: "8080"
        pathPrefix: "/check" # Middleware check handler
        headersToUpstreamOnAllow:
          - "x-nomos-authorization"
          - "x-nomos-app-id"
          - "x-nomos-idp"
        headersToDownstreamOnDeny:
          - "x-nomos-error"
          - "x-nomos-param"
        includeRequestHeadersInCheck:
          - "authorization"
          - "x-target-service"
          - "x-original-uri"
          - "x-original-path"
          - "x-original-method"
```
