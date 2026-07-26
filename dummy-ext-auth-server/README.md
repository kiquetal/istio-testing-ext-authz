# Dummy External Authorization Server in Go

This directory contains a custom Go-based HTTP external authorization server that logs all incoming headers to stdout. This is perfect for debugging and seeing exactly what headers Istio/Envoy forwards to the external auth service.

## How to Build and Deploy to Minikube

To build the image directly inside your Minikube cluster (avoiding the need to push to an external registry), follow these rules:

1.  **Point your local terminal's Docker daemon to Minikube's Docker daemon**:
    ```bash
    eval $(minikube -p auth-ext docker-env)
    ```

2.  **Build the Docker image**:
    Run this command from within this directory (`dummy-ext-auth-server`):
    ```bash
    docker build -t dummy-ext-auth-server:latest .
    ```

3.  **Deploy to Minikube**:
    From the root of the repository, delete the old simulation deployment and apply the custom Go one:
    ```bash
    # Remove the generic test server
    kubectl delete deployment ext-authz -n foo

    # Apply the Go-based deployment
    kubectl apply -f manifest/dummy-ext-auth-server.yaml
    ```

4.  **Inspect received headers in real-time**:
    ```bash
    kubectl logs -n foo deployment/dummy-ext-auth-server -c ext-auth-server -f
    ```
