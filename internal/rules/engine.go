package rules

import (
	"fmt"
	"strings"
	"time"

	"github.com/proxydesk/proxydesk/internal/model"
)

type MatchType string

const (
	MatchExact  MatchType = "exact"
	MatchSuffix MatchType = "suffix"
	MatchList   MatchType = "list"
	MatchAll    MatchType = "all"
)

type DNSRule struct {
	ID         int       `json:"id"`
	Priority   int       `json:"priority"`
	Enabled    bool      `json:"enabled"`
	MatchType  MatchType `json:"match_type"`
	Pattern    string    `json:"pattern"`
	Action     string    `json:"action"` // "group", "block", "local_record"
	DNSGroupID int       `json:"dns_group_id,omitempty"`
	LocalIPv4  string    `json:"local_ipv4,omitempty"`
	LocalIPv6  string    `json:"local_ipv6,omitempty"`
}

type RoutingRule struct {
	ID             int       `json:"id"`
	Priority       int       `json:"priority"`
	Enabled        bool      `json:"enabled"`
	MatchType      MatchType `json:"match_type"`
	Pattern        string    `json:"pattern"`
	Action         string    `json:"action"` // "proxy", "pool", "block", "direct"
	TargetProxyID  *int      `json:"target_proxy_id,omitempty"`
	TargetPoolID   *int      `json:"target_pool_id,omitempty"`
	ResolutionMode string    `json:"resolution_mode"` // "remote_dns" or "managed_dns"
	DNSGroupID     *int      `json:"dns_group_id,omitempty"`
}

// MatchDomain checks whether domain matches pattern according to matchType,
// enforcing strict label boundary on suffix matches (e.g., suffix "example.com"
// matches "example.com" and "sub.example.com", but NEVER "badexample.com").
func MatchDomain(domain string, matchType MatchType, pattern string) bool {
	d := normalizeDomain(domain)
	if d == "" && matchType != MatchAll {
		return false
	}
	switch matchType {
	case MatchAll:
		return true
	case MatchExact:
		return d == normalizeDomain(pattern)
	case MatchSuffix:
		suf := strings.TrimPrefix(normalizeDomain(pattern), ".")
		if suf == "" {
			return false
		}
		return d == suf || strings.HasSuffix(d, "."+suf)
	case MatchList:
		for _, item := range strings.Split(pattern, ",") {
			tok := strings.TrimSpace(item)
			if tok == "" {
				continue
			}
			if strings.HasPrefix(tok, "*.") || strings.HasPrefix(tok, ".") {
				if MatchDomain(d, MatchSuffix, strings.TrimPrefix(tok, "*")) {
					return true
				}
			} else if MatchDomain(d, MatchExact, tok) {
				return true
			}
		}
		return false
	default:
		return false
	}
}

// IsInternalDomain detects single-label or RFC 6762 / internal corporate suffixes (.local, .internal, .lan, .corp, .home.arpa)
// that must never leak to public fallback DNS resolvers without explicit permission (Increment F).
func IsInternalDomain(domain string) bool {
	d := normalizeDomain(domain)
	if !strings.Contains(d, ".") {
		return true
	}
	for _, suf := range []string{"local", "internal", "lan", "corp", "intranet", "home.arpa", "localhost"} {
		if d == suf || strings.HasSuffix(d, "."+suf) {
			return true
		}
	}
	return false
}

// EvaluateDNS selects the matching DNSRule for domain and produces a structured DecisionTrace.
func EvaluateDNS(domain string, rules []DNSRule, defaultGroupID int, now time.Time) (DNSRule, model.DecisionTrace) {
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		if MatchDomain(domain, r.MatchType, r.Pattern) {
			policy := fmt.Sprintf("action=%s", r.Action)
			if r.Action == "group" {
				policy = fmt.Sprintf("dns_group:%d", r.DNSGroupID)
			}
			return r, model.DecisionTrace{
				Timestamp:       now,
				Component:       "dns",
				RuleMatched:     fmt.Sprintf("dns_rule#%d (%s:%s)", r.ID, r.MatchType, r.Pattern),
				DNSPolicy:       policy,
				SelectionReason: fmt.Sprintf("matched priority %d DNS rule #%d", r.Priority, r.ID),
			}
		}
	}
	def := DNSRule{
		ID:         0,
		Priority:   9999,
		Enabled:    true,
		MatchType:  MatchAll,
		Pattern:    "*",
		Action:     "group",
		DNSGroupID: defaultGroupID,
	}
	return def, model.DecisionTrace{
		Timestamp:       now,
		Component:       "dns",
		RuleMatched:     "default_dns_policy",
		DNSPolicy:       fmt.Sprintf("dns_group:%d", defaultGroupID),
		SelectionReason: "no explicit DNS rule matched; using default DNS group",
	}
}

// EvaluateRoute selects the matching RoutingRule for domain/host and produces a structured DecisionTrace
// that explicitly distinguishes Remote DNS from Managed DNS (Increment G).
func EvaluateRoute(host string, rules []RoutingRule, defaultResolutionMode string, strictProxyOnly bool, now time.Time) (RoutingRule, model.DecisionTrace) {
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		if MatchDomain(host, r.MatchType, r.Pattern) {
			mode := r.ResolutionMode
			if mode == "" {
				mode = defaultResolutionMode
			}
			dnsDesc := "remote_dns (resolved by upstream proxy; local DNS rules bypassed)"
			if mode == "managed_dns" {
				if r.DNSGroupID != nil {
					dnsDesc = fmt.Sprintf("managed_dns via dns_group:%d (resolved locally, Host/SNI preserved)", *r.DNSGroupID)
				} else {
					dnsDesc = "managed_dns via matched DNS rule (resolved locally, Host/SNI preserved)"
				}
			}
			return r, model.DecisionTrace{
				Timestamp:       now,
				Component:       "gateway",
				RuleMatched:     fmt.Sprintf("route_rule#%d (%s:%s)", r.ID, r.MatchType, r.Pattern),
				ResolutionMode:  mode,
				DNSPolicy:       dnsDesc,
				RouteAction:     r.Action,
				SelectionReason: fmt.Sprintf("matched priority %d routing rule #%d -> %s", r.Priority, r.ID, r.Action),
			}
		}
	}

	defAction := "pool"
	if !strictProxyOnly {
		defAction = "direct"
	}
	defRule := RoutingRule{
		ID:             0,
		Priority:       9999,
		Enabled:        true,
		MatchType:      MatchAll,
		Pattern:        "*",
		Action:         defAction,
		ResolutionMode: defaultResolutionMode,
	}
	return defRule, model.DecisionTrace{
		Timestamp:       now,
		Component:       "gateway",
		RuleMatched:     "default_route_policy",
		ResolutionMode:  defaultResolutionMode,
		RouteAction:     defAction,
		SelectionReason: fmt.Sprintf("no explicit routing rule matched; default action=%s (strict_proxy_only=%v)", defAction, strictProxyOnly),
	}
}

func normalizeDomain(d string) string {
	d = strings.ToLower(strings.TrimSpace(d))
	return strings.TrimSuffix(d, ".")
}
