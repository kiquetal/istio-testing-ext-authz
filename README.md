# Istio External Authorization Testing (`auth-ext`)

This repository contains the configuration and manifests to test Istio's External Authorization feature on a local Kubernetes cluster.

## Environment Setup

### Minikube Cluster
A local Minikube cluster has been started with the profile name `auth-ext`:

```bash
minikube start -p auth-ext
```

To verify the active context and cluster:
```bash
kubectl config current-context
# Should output: auth-ext
```

---

## Architecture & Codebase

This setup consists of four primary components:
1.  **Istio Helm Values**: Configures Istio control plane to register external authorizers.
2.  **Go External Authorizer (`dummy-ext-auth-server`)**: A custom Go service that intercepts requests, decodes a fake JWT token payload, and matches the parsed MSISDN field against the incoming HTTP header to make authorization decisions.
3.  **Go Protected Application (`dummy-svc-app`)**: A custom Go service that handles deep paths (such as `/v1/customer/*`) and prints received headers and details.
4.  **Testing Environment (`curl-test-pod`)**: A persistent in-mesh pod to run interactively with `curlimages/curl`.

### Codebase Paths
*   **[dummy-ext-auth-server/](file:///mydata/codes/2026/istio-testing-ext-authz/dummy-ext-auth-server)**: Custom Go external authorizer codebase.
*   **[dummy-svc-app/](file:///mydata/codes/2026/istio-testing-ext-authz/dummy-svc-app)**: Custom Go target application codebase.

### Manifest Directory
All deployment and configuration manifests are located in:
*   [manifest/istiod-values.yaml](file:///mydata/codes/2026/istio-testing-ext-authz/manifest/istiod-values.yaml): Custom values for `istio/istiod` registering the authorizer.
*   [manifest/dummy-ext-auth-server.yaml](file:///mydata/codes/2026/istio-testing-ext-authz/manifest/dummy-ext-auth-server.yaml): Deploying the Go authorizer.
*   [manifest/dummy-svc-app.yaml](file:///mydata/codes/2026/istio-testing-ext-authz/manifest/dummy-svc-app.yaml): Deploying the target application and `AuthorizationPolicy` protecting `/v1/customer/*`.
*   [manifest/curl-test-pod.yaml](file:///mydata/codes/2026/istio-testing-ext-authz/manifest/curl-test-pod.yaml): Deploying the in-mesh persistent testing pod.

For interactive curl testing steps, see **[test-curl.md](file:///mydata/codes/2026/istio-testing-ext-authz/test-curl.md)**.

---

## Detailed Configuration & Flow

### 1. Registering the Provider (`istiod-values.yaml`)
Registered as an HTTP extension provider under `meshConfig.extensionProviders`:

```yaml
meshConfig:
  extensionProviders:
  - name: "ext-authz-http"
    envoyExtAuthzHttp:
      service: "ext-authz.foo.svc.cluster.local"
      port: 8000
      includeRequestHeadersInCheck: ["authorization", "cookie", "x-ext-authz"]
      headersToUpstreamOnAllow: ["x-auth-user", "x-auth-email"]
      headersToDownstreamOnDeny: ["content-type", "x-auth-reason"]
```

*   **`includeRequestHeadersInCheck`**: Forwards `authorization` (the JWT) from the incoming request to the authorizer.
*   **`headersToUpstreamOnAllow`**: Injects authorization metadata (`X-Auth-User`, `X-Auth-Email`) on success to the backend.

### 2. Path-Based JWT Verification Logic
When a client requests `http://dummy-svc-app:8080/v1/customer/{msisdn}` (e.g. `/v1/customer/123456789`):
1.  **Envoy** intercepts the request and forwards the request path and the `Authorization` header to **`dummy-ext-auth-server`**.
2.  **`dummy-ext-auth-server`** parses the `msisdn` directly from the URL path segment (extracting the last segment).
3.  It base64-decodes the Bearer JWT token payload:
    `{"name":"Alice","msisdn":"123456789"}`
4.  It compares the **`msisdn` value from the decoded token** with the **MSISDN parsed from the URL path**.
5.  If they match: returns `200 OK`, injects user headers, and Envoy allows the request to pass.
6.  If they mismatch (e.g., trying to access `/v1/customer/3434234234`): returns `403 Forbidden` with a custom `x-auth-reason: path-msisdn-mismatch` header.

#### Architecture Sequence Flow (Mermaid)

```mermaid
sequenceDiagram
    autonumber
    actor Client
    participant Envoy as Envoy Sidecar (Target Pod)
    participant Auth as Go External Authorizer (dummy-ext-auth-server)
    participant App as Target Application (dummy-svc-app)

    Client->>Envoy: GET /v1/customer/123456789<br/>Authorization: Bearer <JWT: msisdn=123456789>
    Note over Envoy: Envoy intercepts request
    Envoy->>Auth: HTTP POST /check<br/>Path: /v1/customer/123456789<br/>Headers: Authorization, Host
    Note over Auth: 1. Extract path MSISDN (123456789)<br/>2. Base64-decode JWT payload<br/>3. Match Token MSISDN with Path MSISDN
    
    alt Match Successful (200 OK)
        Auth-->>Envoy: 200 OK<br/>X-Auth-User: Alice<br/>X-Auth-Email: alice@example.com
        Note over Envoy: Inject custom identity headers
        Envoy->>App: GET /v1/customer/123456789<br/>X-Auth-User: Alice<br/>X-Auth-Email: alice@example.com
        App-->>Envoy: 200 OK (JSON Data)
        Envoy-->>Client: 200 OK (JSON Data)
    else Mismatch Detected (403 Forbidden)
        Auth-->>Envoy: 403 Forbidden<br/>Content-Type: application/json<br/>x-auth-reason: path-msisdn-mismatch
        Note over Envoy: Short-circuit request
        Envoy-->>Client: 403 Forbidden (Error JSON)
    end
```


---

## Installation & Deployment Steps

1.  **Add and update the Istio Helm repository**:
    ```bash
    helm repo add istio https://istio-release.storage.googleapis.com/charts
    helm repo update
    ```

2.  **Install Istio Base (containing CRDs)**:
    ```bash
    helm install istio-base istio/base -n istio-system --create-namespace
    ```

3.  **Install Istiod**:
    ```bash
    helm install istiod istio/istiod -n istio-system --values manifest/istiod-values.yaml
    ```

4.  **Build images inside Minikube's Local Docker Registry**:
    ```bash
    minikube -p auth-ext image build -t dummy-ext-auth-server:latest dummy-ext-auth-server/
    minikube -p auth-ext image build -t dummy-svc-app:latest dummy-svc-app/
    ```

5.  **Apply manifests**:
    ```bash
    kubectl apply -f manifest/dummy-ext-auth-server.yaml
    # Deploy an active ext-authz service selector pointing to the deployment
    kubectl apply -f manifest/ext-authz.yaml 
    kubectl apply -f manifest/dummy-svc-app.yaml
    kubectl apply -f manifest/curl-test-pod.yaml
    ```

6.  **Verify Pod Readiness**:
    ```bash
    kubectl get pods -n foo
    # Output should show dummy-ext-auth-server, dummy-svc-app, and curl-test-pod fully Running (2/2 ready)
    ```

---

## Generating Fake Authorization Tokens

To simulate a JWT token with a custom `name` and `msisdn`, follow these steps:

1.  **Draft your JSON Payload**:
    ```json
    {"name":"Alice","msisdn":"123456789"}
    ```

2.  **Base64 encode the Payload segment**:
    In your terminal, run:
    ```bash
    echo -n '{"name":"Alice","msisdn":"123456789"}' | base64
    # Outputs: eyJuYW1lIjoiQWxpY2UiLCJtc2lzZG4iOiIxMjM0NTY3ODkifQ==
    ```

3.  **Construct the Bearer Token**:
    JWTs consist of three parts (`Header.Payload.Signature`) separated by periods. We use a dummy header (`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9`) and signature (`signature`):
    ```http
    Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiQWxpY2UiLCJtc2lzZG4iOiIxMjM0NTY3ODkifQ==.signature
    ```

---

## JSON Deny Responses

When the external authorizer blocks a request, it returns a structured JSON payload with `403 Forbidden` rather than plain text, facilitating client-side parsing:

```json
{
  "status": 403,
  "error": "Forbidden",
  "message": "The token's MSISDN does not match the requested path's MSISDN.",
  "reason": "path-msisdn-mismatch"
}
```

---

## Security Auditing: Tracking Cross-Tenant Access Violations

To detect malicious scans, credential stuffing, or tenant isolation breaches, the external authorizer must log all path/JWT mismatches as high-severity security events.

### 1. Structured Logging Specification
When a `path-msisdn-mismatch` is triggered, the authorizer should output a structured JSON log to `stdout` for ingestion by SIEM/aggregators (e.g., Elasticsearch, Splunk, Datadog):

```json
{
  "timestamp": "2026-07-26T03:38:13Z",
  "level": "WARN",
  "event": "tenant-access-violation",
  "target_service": "dummy-svc-app:8080",
  "request_id": "b8eea1b2-2900-4347-9653-ccd9f6572f8b",
  "client_identity": "spiffe://cluster.local/ns/foo/sa/default",
  "token_claims": {
    "user_name": "Alice",
    "token_msisdn": "123456789"
  },
  "requested_resource": {
    "path": "/v1/customer/3434234234",
    "extracted_msisdn": "3434234234"
  },
  "action": "DENY"
}
```

### 2. Audit Fields Matrix

| Log Field | Description | Purpose in Forensics |
| :--- | :--- | :--- |
| `event` | Hardcoded classification: `tenant-access-violation` | Allows security filters to easily aggregate all cross-tenant violations. |
| `client_identity` | Parsed from `X-Forwarded-Client-Cert` (SPIFFE ID) | Identifies exactly *which* service inside the mesh initiated the call. |
| `token_claims.user_name` | Parsed from the token payload | Identifies the authenticated human caller name. |
| `token_claims.token_msisdn` | Parsed from the token payload | Identifies the MSISDN ownership claims tied to the token. |
| `requested_resource.extracted_msisdn` | Parsed from URL path parameter | Identifies the target MSISDN they attempted to read/modify. |
| `request_id` | Original Envoy trace header | Allows correlating the denial with distributed APM traces (Jaeger/Zipkin). |

### 3. Alarm and Telemetry Guidelines
*   **Prometheus Metric**: Expose an incremental counter:
    ```prometheus
    nomos_auth_violations_total{service="dummy-svc-app", reason="path-msisdn-mismatch"}
    ```
*   **SIEM Alarm**: Configure an alarm in your log aggregator to trigger whenever:
    *   An individual token triggers $> 5$ violations in under 5 minutes.
    *   A single IP or SPIFFE client identity triggers $> 10$ violations on any service (indicates automated API scraping/brute force).

---

## Run Validation Tests
Check **[test-curl.md](file:///mydata/codes/2026/istio-testing-ext-authz/test-curl.md)** for full testing details and copy-pasteable curls to test mismatched and matching MSISDN validation!


