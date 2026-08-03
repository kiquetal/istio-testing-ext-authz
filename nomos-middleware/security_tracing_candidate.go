package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

// ─────────────────────────────────────────────────────────────────────────────
// Tracer instance
// ─────────────────────────────────────────────────────────────────────────────

var securityTracer = otel.Tracer("nomos-security-interceptor")

// ─────────────────────────────────────────────────────────────────────────────
// [CRITICAL] Root span — must carry target_service, original_path, request_id
// ─────────────────────────────────────────────────────────────────────────────

// TraceSecurityCheck initializes the parent audit span, extracting trace context
// from incoming Envoy headers. This span is the root of the entire authorization
// waterfall — it MUST carry enough context to filter traces by service and path.
func TraceSecurityCheck(r *http.Request) (context.Context, trace.Span) {
	// Extract distributed trace context propagated by Envoy/Istio
	ctx := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))

	// Resolve original request details (Envoy forwards these)
	originalPath := r.Header.Get("x-original-uri")
	if originalPath == "" {
		originalPath = r.Header.Get("x-original-path")
	}
	if originalPath == "" {
		originalPath = r.URL.Path
	}

	originalMethod := r.Header.Get("x-original-method")
	if originalMethod == "" {
		originalMethod = r.Method
	}

	targetService := r.Header.Get("x-target-service")
	requestID := r.Header.Get("x-request-id")

	ctx, span := securityTracer.Start(ctx, "AuthorizationCheck",
		trace.WithSpanKind(trace.SpanKindServer),
	)

	// ── CRITICAL: These attributes allow filtering by service/path in any trace backend
	span.SetAttributes(
		attribute.String("security.component", "nomos-middleware"),
		attribute.String("nomos.target_service", targetService),
		attribute.String("http.target", originalPath),
		attribute.String("http.method", originalMethod),
		attribute.String("http.client_ip", r.RemoteAddr),
		attribute.String("nomos.request_id", requestID),
	)

	return ctx, span
}

// ─────────────────────────────────────────────────────────────────────────────
// [CRITICAL] Nomos resolution span — isolate network latency to rule store
// ─────────────────────────────────────────────────────────────────────────────

// TraceNomosResolution records the call (or cache hit) to the Nomos rules engine.
// Without this span, you cannot distinguish "nomos was slow" from "enrichment was slow"
// when debugging latency spikes.
func TraceNomosResolution(ctx context.Context, proxy, aud, iss string, cached bool, duration time.Duration, rulesCount int, err error) {
	_, span := securityTracer.Start(ctx, "ResolveNomosRules",
		trace.WithSpanKind(trace.SpanKindClient),
	)
	defer span.End()

	span.SetAttributes(
		attribute.String("nomos.proxy", proxy),
		attribute.String("nomos.audience", aud),
		attribute.String("nomos.issuer", iss),
		attribute.Bool("nomos.cache_hit", cached),
		attribute.Int64("nomos.resolution_ms", duration.Milliseconds()),
		attribute.Int("nomos.rules_returned", rulesCount),
	)

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "Nomos resolution failed")
		span.SetAttributes(attribute.String("nomos.failure_type", classifyNomosError(err)))
	}
}

// classifyNomosError categorizes the failure for alerting/dashboards.
func classifyNomosError(err error) string {
	msg := err.Error()
	switch {
	case contains(msg, "status code 403"):
		return "ACCESS_DENIED"
	case contains(msg, "timeout") || contains(msg, "deadline exceeded"):
		return "TIMEOUT"
	case contains(msg, "connection refused") || contains(msg, "no such host"):
		return "UNREACHABLE"
	default:
		return "UNKNOWN"
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// [HIGH] Rule matching span — which rule matched (or none)
// ─────────────────────────────────────────────────────────────────────────────

// TraceRuleMatch records the path-pattern matching phase. When operators debug
// "why was this path denied?", this span shows whether a rule matched at all,
// which rule it was, and how many rules were evaluated.
func TraceRuleMatch(ctx context.Context, matchedRuleID, matchedPattern, originalPath string, rulesEvaluated int) (context.Context, trace.Span) {
	ctx, span := securityTracer.Start(ctx, "MatchRule",
		trace.WithSpanKind(trace.SpanKindInternal),
	)

	span.SetAttributes(
		attribute.Int("nomos.rules_evaluated", rulesEvaluated),
		attribute.String("nomos.original_path", originalPath),
	)

	if matchedRuleID != "" {
		span.SetAttributes(
			attribute.String("nomos.matched_rule_id", matchedRuleID),
			attribute.String("nomos.matched_pattern", matchedPattern),
		)
	} else {
		span.SetAttributes(attribute.Bool("nomos.no_rule_match", true))
	}

	return ctx, span
}

// ─────────────────────────────────────────────────────────────────────────────
// Client identity binding (non-repudiation)
// ─────────────────────────────────────────────────────────────────────────────

// BindClientIdentity records verified JWT metadata onto the trace.
func BindClientIdentity(span trace.Span, claims map[string]any) {
	var subject, issuer, audience string

	if sub, ok := claims["sub"].(string); ok {
		subject = sub
	}
	if iss, ok := claims["iss"].(string); ok {
		issuer = iss
	}
	if aud, ok := claims["aud"]; ok {
		switch v := aud.(type) {
		case string:
			audience = v
		case []any:
			if len(v) > 0 {
				if s, ok := v[0].(string); ok {
					audience = s
				}
			}
		}
	}

	span.SetAttributes(
		attribute.String("enduser.id", subject),
		attribute.String("enduser.issuer", issuer),
		attribute.String("enduser.audience", audience),
	)
}

// ─────────────────────────────────────────────────────────────────────────────
// BOLA/IDOR evaluation span
// ─────────────────────────────────────────────────────────────────────────────

// TraceBOLAEvaluation creates a high-fidelity audit span for Broken Object Level
// Authorization checks. Each validation param gets its own span for precise waterfall.
func TraceBOLAEvaluation(ctx context.Context, level int, ruleID, pattern, paramName, expectedVal, actualVal, validationType string) (bool, trace.Span) {
	spanName := fmt.Sprintf("EvaluateBOLA/L%d/%s", level, paramName)
	_, span := securityTracer.Start(ctx, spanName,
		trace.WithSpanKind(trace.SpanKindInternal),
	)

	span.SetAttributes(
		attribute.String("security.rule_id", ruleID),
		attribute.String("security.rule_pattern", pattern),
		attribute.Int("security.validation_level", level),
		attribute.String("security.bola.checked_parameter", paramName),
		attribute.String("security.bola.validation_type", validationType),
	)

	// Determine violation based on validation type
	var isViolation bool
	switch validationType {
	case "equals":
		isViolation = expectedVal != actualVal
	case "contains":
		// For "contains", the caller should pre-resolve and pass the result.
		// If expectedVal == "" it means the value was NOT found in the list.
		isViolation = expectedVal == ""
	default:
		isViolation = expectedVal != actualVal
	}

	if isViolation {
		span.SetAttributes(
			attribute.Bool("security.authz_violation", true),
			attribute.String("security.violation_type", "BOLA_IDOR_ATTEMPT"),
			attribute.String("security.expected_ownership", expectedVal),
			attribute.String("security.target_resource", actualVal),
			attribute.String("security.remediation_action", "DENY_ACCESS"),
		)
		span.SetStatus(codes.Error, "BOLA/IDOR Security Violation Detected")
	} else {
		span.SetAttributes(
			attribute.Bool("security.authz_violation", false),
			attribute.String("security.audit.status", "PASS"),
		)
	}

	return isViolation, span
}

// ─────────────────────────────────────────────────────────────────────────────
// Dynamic enrichment audit span
// ─────────────────────────────────────────────────────────────────────────────

// TraceDynamicEnrichment audits external data lookups that expand authorization context.
func TraceDynamicEnrichment(ctx context.Context, endpoint, domainFrom string, cached bool, duration time.Duration, success bool, err error) {
	_, span := securityTracer.Start(ctx, "AuditDynamicEnrichment",
		trace.WithSpanKind(trace.SpanKindClient),
	)
	defer span.End()

	span.SetAttributes(
		attribute.String("security.enrichment.endpoint", endpoint),
		attribute.String("security.enrichment.source_type", domainFrom),
		attribute.Bool("security.enrichment.cache_hit", cached),
		attribute.Int64("security.enrichment.duration_ms", duration.Milliseconds()),
	)

	if !success {
		if err != nil {
			span.RecordError(err)
		}
		span.SetStatus(codes.Error, "Enrichment failed or source untrusted")
		span.SetAttributes(attribute.String("security.audit.failure_stage", "ENRICHMENT_FAILURE"))
	} else {
		span.SetAttributes(attribute.Bool("security.enrichment.success", true))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Final decision span
// ─────────────────────────────────────────────────────────────────────────────

// AuditFinalDecision completes the root span with the final permit/deny verdict.
func AuditFinalDecision(span trace.Span, allowed bool, reasonCode, message string) {
	if allowed {
		span.SetAttributes(
			attribute.String("security.decision", "ALLOW"),
		)
		span.SetStatus(codes.Ok, "Authorization Approved")
	} else {
		span.SetAttributes(
			attribute.String("security.decision", "DENY"),
			attribute.String("security.reason_code", reasonCode),
			attribute.String("security.reason_message", message),
		)
		span.SetStatus(codes.Error, fmt.Sprintf("Authorization Denied: %s", reasonCode))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// [HIGH] Structured audit log — works WITHOUT OpenTelemetry collector
// ─────────────────────────────────────────────────────────────────────────────

// SecurityAuditEntry is the structured JSON line emitted at the end of every
// authorization check. This provides day-one observability with just kubectl logs
// or any log aggregator (CloudWatch Logs, Loki, Fluentd, etc.)
type SecurityAuditEntry struct {
	Timestamp     string `json:"ts"`
	RequestID     string `json:"rid"`
	TargetService string `json:"svc"`
	Path          string `json:"path"`
	Method        string `json:"method"`
	Subject       string `json:"sub"`
	Issuer        string `json:"iss"`
	Audience      string `json:"aud"`
	MatchedRule   string `json:"rule,omitempty"`
	RulePattern   string `json:"pattern,omitempty"`
	Decision      string `json:"decision"`
	Reason        string `json:"reason,omitempty"`
	DurationMs    int64  `json:"dur_ms"`
	CacheHit      bool   `json:"cache_hit"`
	Enriched      bool   `json:"enriched"`
}

// EmitSecurityAuditLog writes a single structured JSON line to stdout.
// This log line is the fallback audit trail when no OTel collector is deployed.
// It contains enough context to answer: "who accessed what, was it allowed, and why?"
func EmitSecurityAuditLog(entry SecurityAuditEntry) {
	entry.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	data, err := json.Marshal(entry)
	if err != nil {
		log.Printf("[AUDIT_ERROR] failed to marshal audit entry: %v", err)
		return
	}
	// Print as a single line — compatible with all log aggregators
	fmt.Println(string(data))
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstring(s, substr))
}

func containsSubstring(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
