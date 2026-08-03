package main

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

// Global tracer instance for security telemetry
var securityTracer = otel.Tracer("nomos-security-interceptor")

// SecurityAuditPayload captures key security context extracted during authorization checks
type SecurityAuditPayload struct {
	TargetService string
	ClientIP      string
	OriginalPath  string
	Method        string
	Subject       string // "sub" from JWT
	Issuer        string // "iss" from JWT
	Audience      string // "aud" from JWT
	RuleID        string // Matched policy rule ID
}

// TraceSecurityCheck initializes the parent audit span, extracting trace context from incoming Envoy headers.
func TraceSecurityCheck(r *http.Request) (context.Context, trace.Span) {
	// Extract the trace context propagated by Envoy
	ctx := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))

	// Start the parent interception span
	ctx, span := securityTracer.Start(ctx, "AuthorizationCheck",
		trace.WithSpanKind(trace.SpanKindServer),
	)

	// Log baseline transport metadata
	span.SetAttributes(
		attribute.String("security.component", "nomos-middleware"),
		attribute.String("http.method", r.Method),
		attribute.String("http.client_ip", r.RemoteAddr),
	)

	return ctx, span
}

// BindClientIdentity records verified client JWT metadata onto the trace for non-repudiation.
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

// TraceBOLAEvaluation runs a high-fidelity audit span specifically for Broken Object Level Authorization
func TraceBOLAEvaluation(ctx context.Context, ruleID, pattern, paramName, expectedVal, pathVal string) (bool, trace.Span) {
	_, span := securityTracer.Start(ctx, "EvaluateBOLA",
		trace.WithSpanKind(trace.SpanKindInternal),
	)

	span.SetAttributes(
		attribute.String("security.rule_id", ruleID),
		attribute.String("security.rule_pattern", pattern),
		attribute.String("security.bola.checked_parameter", paramName),
	)

	// Compare ownership context (BOLA detection)
	isViolation := expectedVal != pathVal

	if isViolation {
		// Log a critical security incident for SIEM alerts
		span.SetAttributes(
			attribute.Bool("security.authz_violation", true),
			attribute.String("security.violation_type", "BOLA_IDOR_ATTEMPT"),
			attribute.String("security.attacker_identity", expectedVal), // Expected ownership value in token
			attribute.String("security.target_resource", pathVal),       // Resource they attempted to access
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

// TraceDynamicEnrichment audits external data lookups that elevate authorization context
func TraceDynamicEnrichment(ctx context.Context, endpoint, domainFrom string, success bool, err error) {
	_, span := securityTracer.Start(ctx, "AuditDynamicEnrichment",
		trace.WithSpanKind(trace.SpanKindClient),
	)
	defer span.End()

	span.SetAttributes(
		attribute.String("security.enrichment.endpoint", endpoint),
		attribute.String("security.enrichment.source_type", domainFrom),
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

// AuditFinalDecision completes the root span with the final permit/deny decision
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
