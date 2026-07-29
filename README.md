# Istio External Authorization (Ext-Authz) Architecture & Testing

This repository provides a production-modeled local testing environment for Istio's **External Authorization** (`CUSTOM` action) capabilities. It demonstrates how to intercept HTTP requests at the Envoy sidecar, delegate authorization decisions to a custom containerized helper based on JSON Web Tokens (JWT) and URL paths, and safely inject verified identities or reject malicious requests.

---

## 🏛️ System Architecture

The following diagram illustrates the deployment topology and security boundaries inside our local Kubernetes cluster:

```text
                                 [ Kubernetes Cluster (Minikube: auth-ext) ]
========================================================================================================
                                                                                                      
        [ Namespace: foo ] (istio-injection=enabled)                                                   
       +---------------------------------------------------------------------------------------+      
       |                                                                                       |      
       |    +------------------------+                        +---------------------------+    |      
       |    |     curl-test-pod      |                        |       dummy-svc-app       |    |      
       |    |                        |                        |                           |    |      
       |    |  +------------------+  |                        |  +---------------------+  |    |      
       |    |  |  curl container  |  |                        |  |    Envoy Proxy      |  |    |      
       |    |  +--------+---------+  |                        |  |  (Intercepts /v1/*) |  |    |      
       |    +-----------|------------+                        +--+----------+----------+--+    |      
                |                                                   |  | (5. Forward App Request)
                | (1. Initiate Request with JWT)                    |  v               |      
                +-------------------------------------------------->|  +------------+  |      
                                                                    |  | Go App     |  |      
                                                                    |  | Container  |  |      
                                                                    |  +------------+  |      
                                                                    |                  |      
                               +-------------------------+          | (2. Check)       |      
                               | dummy-ext-auth-server   |          |                  |      
                               |                         |<---------+                  |      
                               |  +-------------------+  |                             |      
                               |  |  Go Auth Server   |  | (3. Respond Allow/Deny)     |      
                               |  |     (Port 8000)   |  +---------------------------->|      
                               |  +-------------------+  |                             |      
                               +-------------------------+                             |      
                                                                                       |      
       +---------------------------------------------------------------------------------------+      
                                                                                                      
========================================================================================================
```

### Component Duties
1. **Client (`curl-test-pod`)**: Acts as an intra-mesh user issuing commands containing a simulated Base64-encoded JWT token representing tenant metadata (e.g., `msisdn`).
2. **Envoy Proxy Sidecar (`dummy-svc-app`)**: Incepts traffic bound for the protected `dummy-svc-app`. Guided by an Istio `AuthorizationPolicy`, it traps all incoming requests targeting `/v1/customer/*` and holds them while executing a side-channel request to the external authorizer.
3. **External Authorizer (`dummy-ext-auth-server`)**: A custom lightweight Go microservice. It parses the incoming path, decodes the fake JWT payload, ensures the identity matches the resource, and returns either `200 OK` (with identity injections) or `403 Forbidden` (with custom error metrics).
4. **Protected Service (`dummy-svc-app`)**: A simple backend that handles safe paths and reads headers (`X-Auth-User`, `X-Auth-Email`) injected by Envoy to authenticate the tenant.

---

## 🔄 Sequence & Interception Flow

The detailed sequence of events for a request validation is captured in the diagram below:

```plantuml
@startuml
!theme spacelab
!option handwritten true
skinparam backgroundColor #f8f9fa
skinparam classFontColor #000000
skinparam classBorderColor #4285F4
skinparam arrowColor #4285F4

actor "Client Pod" as Client
participant "Envoy Sidecar\n(dummy-svc-app)" as Envoy
participant "Go External Authorizer\n(dummy-ext-auth-server)" as Auth
database "Target Application\n(dummy-svc-app)" as App

Client -> Envoy: GET /v1/customer/123456789\nAuthorization: Bearer <JWT: msisdn=123456789>
activate Envoy

Note over Envoy: Interception rule triggers:\nAuthorizationPolicy CUSTOM action

Envoy -> Auth: POST /check (HTTP/8000)\nHeaders: [Authorization, Cookie, X-Ext-Authz]\nPath: /v1/customer/123456789
activate Auth

Note over Auth: 1. Extract Path MSISDN (123456789)\n2. Base64-decode token payload\n3. Verify: Path MSISDN == Token MSISDN

alt Match Successful (200 OK)
    Auth --> Envoy: 200 OK\nHeaders: X-Auth-User: Alice, X-Auth-Email: alice@example.com
    Note over Envoy: Mutate original request:\nInject X-Auth-User & X-Auth-Email
    Envoy -> App: GET /v1/customer/123456789\nHeaders: [X-Auth-User, X-Auth-Email]
    activate App
    App --> Envoy: 200 OK (JSON Body)
    deactivate App
    Envoy --> Client: 200 OK (User Resource Data)
else Mismatch / Unauthorized (403 Forbidden)
    Auth --> Envoy: 403 Forbidden\nHeaders: X-Auth-Reason: path-msisdn-mismatch\nBody: { "error": "Forbidden", ... }
    Note over Envoy: Short-circuit connection
    Envoy --> Client: 403 Forbidden (Error Payload)
end
deactivate Auth
deactivate Envoy

footer Co-authored by kiquetal
@enduml
```

---

## 🛠️ Configuration Details

### 1. Extension Provider Registration
The Istio control plane is told how to find and speak with the custom check server in `manifest/istiod-values.yaml`:

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

### 2. Header Mapping Matrix

| Configuration Attribute | Managed Headers | Purpose |
| :--- | :--- | :--- |
| **`includeRequestHeadersInCheck`** | `Authorization`, `Cookie`, `X-Ext-Authz` | Forwards these headers from the client's request to the authorization server for processing. |
| **`headersToUpstreamOnAllow`** | `X-Auth-User`, `X-Auth-Email` | Headers set by the Authorizer on success that Envoy will inject into the request forwarded to the backend. |
| **`headersToDownstreamOnDeny`** | `Content-Type`, `X-Auth-Reason` | Headers set by the Authorizer on failure that Envoy will return to the client in the `403 Forbidden` response. |

---

## 🛡️ Threat Mitigation & Isolation

This architecture addresses several key API security threats:

*   **BOLA / IDOR (Broken Object Level Authorization)**: A malicious actor might have a valid token for tenant `A` but attempt to fetch resources belonging to tenant `B` (`/v1/customer/B`). Because the authorizer cross-references the resource identifier parsed from the path against the cryptographically encoded claims in the JWT, these attempts are instantly blocked at the edge proxy (Envoy) before hitting the application.
*   **Token Spoofing**: Since the external check logic validates JWT structures and is positioned behind Envoy, arbitrary unauthenticated calls targeting protected service ports inside the mesh are prohibited.
*   **Audit Trail Preservation**: Cross-tenant violations are captured at the authorization layer. Real-time structured security logs allow operations teams to configure high-priority SIEM alarms.

---

## 🚀 Get Started & Testing

For full installation commands, container image building, and manual verification steps, consult the standard documentation:
*   **Deployment and Run Instructions**: See [test-curl.md](file:///mydata/codes/2026/istio-testing-ext-authz/test-curl.md) to set up and deploy the manifests.
*   **Interactive curl scenarios**: [test-curl.md](file:///mydata/codes/2026/istio-testing-ext-authz/test-curl.md) for actual validation testing.
