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

## Istio Installation & Configuration

Istio is installed using the `istio-operator` manifest which registers external authorization providers in `MeshConfig`.

### Manifest Directory
The installation manifest is located in:
*   [manifest/istio-operator.yaml](file:///mydata/codes/2026/istio-testing-ext-authz/manifest/istio-operator.yaml)

### Manifest Structure & Details
The `istio-operator.yaml` manifest defines an `IstioOperator` configuration. The key component is the `meshConfig.extensionProviders` section, which registers external services that Istio can call to make authorization decisions:

```yaml
apiVersion: install.istio.io/v1alpha1
kind: IstioOperator
spec:
  profile: demo
  meshConfig:
    accessLogFile: /dev/stdout
    extensionProviders:
    - name: "ext-authz-http"
      envoyExtAuthzHttp:
        service: "ext-authz.foo.svc.cluster.local"
        port: "8000"
        includeRequestHeadersInCheck: ["authorization", "cookie"]
        headersToUpstreamOnAllow: ["x-auth-user", "x-auth-email"]
        headersToDownstreamOnDeny: ["content-type", "x-auth-reason"]
    - name: "ext-authz-grpc"
      envoyExtAuthzGrpc:
        service: "ext-authz.foo.svc.cluster.local"
        port: "9000"
```

#### Detailed Explanation of Key Parameters:
- **`profile: demo`**: Uses the Istio `demo` profile, which is pre-configured with egress and ingress gateways, suitable for testing and development.
- **`meshConfig.accessLogFile: /dev/stdout`**: Configures Envoy proxies to print access logs to standard output, making troubleshooting easier.
- **`extensionProviders`**:
  - **`ext-authz-http`**:
    - **`envoyExtAuthzHttp`**: Specifies an HTTP-based external authorization service.
    - **`service`**: Points to the FQDN of the external authorizer service (`ext-authz.foo.svc.cluster.local`).
    - **`port`**: The service port (`8000`).
    - **`includeRequestHeadersInCheck`**: Specifies headers (e.g., `authorization`, `cookie`) that should be forwarded from the client request to the authorization service.
    - **`headersToUpstreamOnAllow`**: Extra headers (like `x-auth-user`, `x-auth-email`) returned by the authorizer on success that will be forwarded to the backend service.
    - **`headersToDownstreamOnDeny`**: Headers returned by the authorizer on denial that will be returned back to the client.
  - **`ext-authz-grpc`**:
    - **`envoyExtAuthzGrpc`**: Specifies a high-performance gRPC-based external authorization service at port `9000`.

### Applying the Installation
To apply this configuration, run:
```bash
istioctl install -f manifest/istio-operator.yaml -y
```

Verify that Istio's components are successfully installed and running:
```bash
kubectl get pods -n istio-system
```
