package main

import (
	"encoding/json"
	"log"
	"net/http"
)

type Response struct {
	Message string              `json:"message"`
	Path    string              `json:"path"`
	Headers map[string][]string `json:"headers"`
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	log.Printf("Received request for path: %s", r.URL.Path)

	resp := Response{
		Message: "Hello from dummy-svc-app!",
		Path:    r.URL.Path,
		Headers: r.Header,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func main() {
	http.HandleFunc("/", handleRequest)
	log.Println("Starting dummy-svc-app on :8080...")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
