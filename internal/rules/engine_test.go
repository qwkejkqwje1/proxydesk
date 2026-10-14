package rules

import (
	"testing"
	"time"
)

func TestSuffixBoundaryAndDualDecisionTrace(t *testing.T) {
	// 1. Suffix boundary check: "example.com" matches "example.com" and "api.example.com", NEVER "evil-example.com"
	if !MatchDomain("example.com", MatchSuffix, "example.com") {
		t.Fatal("exact root must match suffix")
	}
	if !MatchDomain("sub.api.example.com.", MatchSuffix, ".example.com") {
		t.Fatal("subdomain must match suffix")
	}
	if MatchDomain("evil-example.com", MatchSuffix, "example.com") {
		t.Fatal("boundary violation: evil-example.com matched suffix example.com")
	}

	// 2. Internal domain detection
	if !IsInternalDomain("intranet.corp.local") || !IsInternalDomain("fileserver") {
		t.Fatal("expected internal domain detection to return true")
	}
	if IsInternalDomain("github.com") {
		t.Fatal("github.com is not an internal domain")
	}

	// 3. Separate DNS and Routing evaluation (Increment G)
	now := time.Now().UTC()
	dnsRules := []DNSRule{
		{ID: 1, Priority: 10, Enabled: true, MatchType: MatchSuffix, Pattern: "corp.internal", Action: "group", DNSGroupID: 2},
	}
	groupID := 2
	poolID := 1
	routeRules := []RoutingRule{
		{
			ID: 5, Priority: 10, Enabled: true, MatchType: MatchSuffix, Pattern: "corp.internal",
			Action: "pool", TargetPoolID: &poolID, ResolutionMode: "managed_dns", DNSGroupID: &groupID,
		},
	}

	dRule, dTrace := EvaluateDNS("git.corp.internal", dnsRules, 1, now)
	rRule, rTrace := EvaluateRoute("git.corp.internal", routeRules, "remote_dns", true, now)

	if dRule.DNSGroupID != 2 || dTrace.DNSPolicy != "dns_group:2" {
		t.Fatalf("unexpected DNS evaluation: rule=%+v trace=%+v", dRule, dTrace)
	}
	if rRule.ResolutionMode != "managed_dns" || rTrace.RouteAction != "pool" {
		t.Fatalf("unexpected Route evaluation: rule=%+v trace=%+v", rRule, rTrace)
	}
}
