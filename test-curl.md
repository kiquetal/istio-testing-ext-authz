# Testing External Authorization using `curlimages/curl`

This guide explains how to spin up a persistent testing pod inside the mesh using the `curlimages/curl` image and perform validation tests on the protected `httpbin` and `dummy-svc-app` services.

---

## 1. Deploy the Curl Pod

A dedicated manifest is provided to launch a persistent `curl-test-pod` running a sleep command, allowing you to run multiple tests interactively.

Deploy the pod using the manifest:
```bash
kubectl apply -f manifest/curl-test-pod.yaml
```

Wait until the pod is fully running:
```bash
kubectl get pod curl-test-pod -n foo -w
```

---

## 2. Basic Tests (with `httpbin`)

Once the pod is ready, execute curl requests inside it using `kubectl exec`.

### Case A: Unauthorized Request (No Header)
Send a request to the protected `/headers` endpoint of the `httpbin` service without sending the authorization header:

```bash
kubectl exec -it curl-test-pod -n foo -- curl -si http://httpbin:8000/headers
```

#### Expected Output
You should receive a `403 Forbidden` response:
```http
HTTP/1.1 403 Forbidden
...
denied: missing Authorization header
```

---

### Case B: Authorized Request (With `x-ext-authz: allow` Header)
Send the request again, but this time specify the header required by the external authorizer:

```bash
kubectl exec -it curl-test-pod -n foo -- curl -si -H "x-ext-authz: allow" http://httpbin:8000/headers
```

#### Expected Output
```http
HTTP/1.1 200 OK
...
```

---

## 3. Advanced JWT & Path-Based Validation Tests (with `dummy-svc-app`)

The custom Go external authorization server performs full path-based token verification. It decodes a base64 encoded JWT payload containing `{"name": "Alice", "msisdn": "123456789"}` and verifies if the value matches the MSISDN specified directly in the URL path segment `/v1/customer/{msisdn}`.

The base64 encoded string of `{"name":"Alice","msisdn":"123456789"}` is:
`eyJuYW1lIjoiQWxpY2UiLCJtc2lzZG4iOiIxMjM0NTY3ODkifQ==`

Using a real-looking Bearer Token format:
`Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiQWxpY2UiLCJtc2lzZG4iOiIxMjM0NTY3ODkifQ==.signature`

---

### Case C: Unauthorized Request (Path MSISDN Mismatch)
Pass the valid JWT (for MSISDN `123456789`), but try to query a different customer's endpoint `/v1/customer/3434234234`:

```bash
kubectl exec -it curl-test-pod -n foo -- curl -si \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiQWxpY2UiLCJtc2lzZG4iOiIxMjM0NTY3ODkifQ==.signature" \
  http://dummy-svc-app:8080/v1/customer/3434234234
```

#### Expected Output
The external authorizer returns `403 Forbidden` because the parsed MSISDN from the JWT (`123456789`) does not match the requested path segment (`3434234234`), preventing cross-tenant access:

```http
HTTP/1.1 403 Forbidden
x-auth-reason: path-msisdn-mismatch
content-type: text/plain; charset=utf-8

denied: Path MSISDN Mismatch
```

---

### Case D: Authorized Request (Path MSISDN Matches JWT)
Pass the valid JWT and query your own endpoint `/v1/customer/123456789`:

```bash
kubectl exec -it curl-test-pod -n foo -- curl -si \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiQWxpY2UiLCJtc2lzZG4iOiIxMjM0NTY3ODkifQ==.signature" \
  http://dummy-svc-app:8080/v1/customer/123456789
```

#### Expected Output
The authorizer accepts the request because the token's MSISDN matches the path MSISDN, and injects context headers (`X-Auth-User`, `X-Auth-Email`) which are successfully forwarded to your application:

```http
HTTP/1.1 200 OK
content-type: application/json

{
  "message": "Hello from dummy-svc-app!",
  "path": "/v1/customer/123456789",
  "headers": {
    "Authorization": ["Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiQWxpY2UiLCJtc2lzZG4iOiIxMjM0NTY3ODkifQ==.signature"],
    "X-Auth-Email": ["alice@example.com"],
    "X-Auth-User": ["Alice"]
  }
}
```
