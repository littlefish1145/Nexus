package iam

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

// PolicyEvaluator evaluates IAM policies against a request context
type PolicyEvaluator struct {
	store *IAMStore
}

// NewPolicyEvaluator creates a new policy evaluator
func NewPolicyEvaluator(store *IAMStore) *PolicyEvaluator {
	return &PolicyEvaluator{store: store}
}

// Evaluate evaluates all applicable policies for a request
// Evaluation order (AWS spec):
// 1. Check for explicit Deny in all applicable policies -> Deny
// 2. Check for explicit Allow in identity-based policies (user + group) -> Allow
// 3. Check for explicit Allow in resource-based policies (bucket policy) -> Allow
// 4. Default ImplicitDeny
func (pe *PolicyEvaluator) Evaluate(ctx *EvalContext) *EvalResult {
	// Collect all applicable policy documents
	var identityPolicies []PolicyDocument
	var resourcePolicies []PolicyDocument

	// 1. Get user's inline policies and attached policies
	user, err := pe.store.GetUser(ctx.Principal)
	if err == nil && user != nil {
		// Inline policies
		identityPolicies = append(identityPolicies, user.InlinePolicies...)

		// Attached managed policies
		for _, policyName := range user.AttachedPolicies {
			policy, err := pe.store.GetPolicy(policyName)
			if err == nil {
				identityPolicies = append(identityPolicies, policy.Document)
			}
		}

		// Group policies
		for _, groupName := range user.Groups {
			group, err := pe.store.GetGroup(groupName)
			if err == nil {
				for _, policyName := range group.AttachedPolicies {
					policy, err := pe.store.GetPolicy(policyName)
					if err == nil {
						identityPolicies = append(identityPolicies, policy.Document)
					}
				}
			}
		}
	}

	// 2. Get bucket policy (resource-based)
	bucketName := extractBucketFromResource(ctx.Resource)
	if bucketName != "" {
		bp, err := pe.store.GetBucketPolicy(bucketName)
		if err == nil {
			resourcePolicies = append(resourcePolicies, bp.Document)
		}
	}

	// Phase 1: Check for explicit Deny across ALL policies
	allPolicies := append(identityPolicies, resourcePolicies...)
	for _, doc := range allPolicies {
		for _, stmt := range doc.Statement {
			if stmt.Effect == EffectDeny {
				if pe.statementMatches(&stmt, ctx) {
					return &EvalResult{
						Decision:  DecisionDeny,
						MatchedBy: stmt.Sid,
					}
				}
			}
		}
	}

	// Phase 2: Check for explicit Allow in identity-based policies
	for _, doc := range identityPolicies {
		for _, stmt := range doc.Statement {
			if stmt.Effect == EffectAllow {
				if pe.statementMatches(&stmt, ctx) {
					return &EvalResult{
						Decision:  DecisionAllow,
						MatchedBy: stmt.Sid,
					}
				}
			}
		}
	}

	// Phase 3: Check for explicit Allow in resource-based policies
	for _, doc := range resourcePolicies {
		for _, stmt := range doc.Statement {
			if stmt.Effect == EffectAllow {
				if pe.statementMatches(&stmt, ctx) {
					return &EvalResult{
						Decision:  DecisionAllow,
						MatchedBy: stmt.Sid,
					}
				}
			}
		}
	}

	// Phase 4: Default implicit deny
	return &EvalResult{
		Decision: DecisionImplicitDeny,
	}
}

// EvaluateWithTempCreds evaluates policies for temporary credentials (STS)
func (pe *PolicyEvaluator) EvaluateWithTempCreds(ctx *EvalContext, rolePolicies []string, inlinePolicy *PolicyDocument) *EvalResult {
	var identityPolicies []PolicyDocument

	// Role's permission policies
	for _, policyName := range rolePolicies {
		policy, err := pe.store.GetPolicy(policyName)
		if err == nil {
			identityPolicies = append(identityPolicies, policy.Document)
		}
	}

	// Inline policy from AssumeRole (scoped down)
	if inlinePolicy != nil {
		identityPolicies = append(identityPolicies, *inlinePolicy)
	}

	// Resource-based policies
	var resourcePolicies []PolicyDocument
	bucketName := extractBucketFromResource(ctx.Resource)
	if bucketName != "" {
		bp, err := pe.store.GetBucketPolicy(bucketName)
		if err == nil {
			resourcePolicies = append(resourcePolicies, bp.Document)
		}
	}

	// Same evaluation logic
	allPolicies := append(identityPolicies, resourcePolicies...)
	for _, doc := range allPolicies {
		for _, stmt := range doc.Statement {
			if stmt.Effect == EffectDeny && pe.statementMatches(&stmt, ctx) {
				return &EvalResult{Decision: DecisionDeny, MatchedBy: stmt.Sid}
			}
		}
	}

	for _, doc := range identityPolicies {
		for _, stmt := range doc.Statement {
			if stmt.Effect == EffectAllow && pe.statementMatches(&stmt, ctx) {
				return &EvalResult{Decision: DecisionAllow, MatchedBy: stmt.Sid}
			}
		}
	}

	for _, doc := range resourcePolicies {
		for _, stmt := range doc.Statement {
			if stmt.Effect == EffectAllow && pe.statementMatches(&stmt, ctx) {
				return &EvalResult{Decision: DecisionAllow, MatchedBy: stmt.Sid}
			}
		}
	}

	return &EvalResult{Decision: DecisionImplicitDeny}
}

// statementMatches checks if a statement matches the evaluation context
func (pe *PolicyEvaluator) statementMatches(stmt *Statement, ctx *EvalContext) bool {
	// Check Action
	if !pe.actionMatches(stmt.Action, ctx.Action) {
		// Check NotAction (inverse match)
		if len(stmt.NotAction) > 0 {
			if pe.actionMatches(stmt.NotAction, ctx.Action) {
				return false // Action is in NotAction list, so this statement doesn't apply
			}
			// Action is NOT in NotAction, so statement applies (fall through to Resource check)
		} else {
			return false
		}
	}

	// Check Resource
	if !pe.resourceMatches(stmt.Resource, ctx.Resource) {
		// Check NotResource
		if len(stmt.NotResource) > 0 {
			if pe.resourceMatches(stmt.NotResource, ctx.Resource) {
				return false
			}
		} else {
			return false
		}
	}

	// Check Principal (for bucket policies)
	if stmt.Principal != nil {
		if !pe.principalMatches(stmt.Principal, ctx.Principal) {
			return false
		}
	}

	// Check Conditions
	if len(stmt.Condition) > 0 {
		if !pe.conditionsMatch(stmt.Condition, ctx) {
			return false
		}
	}

	return true
}

// actionMatches checks if the requested action matches any of the policy actions
func (pe *PolicyEvaluator) actionMatches(policyActions []string, requestAction string) bool {
	for _, action := range policyActions {
		if pe.matchAction(action, requestAction) {
			return true
		}
	}
	return false
}

// matchAction matches a single action pattern against a request action
func (pe *PolicyEvaluator) matchAction(pattern, action string) bool {
	if pattern == "*" {
		return true
	}

	pattern = strings.ToLower(pattern)
	action = strings.ToLower(action)

	if pattern == action {
		return true
	}

	// Handle service:* (e.g., s3:*)
	if strings.HasSuffix(pattern, ":*") {
		service := strings.TrimSuffix(pattern, ":*")
		return strings.HasPrefix(action, service+":")
	}

	return false
}

// resourceMatches checks if the requested resource matches any of the policy resources
func (pe *PolicyEvaluator) resourceMatches(policyResources []string, requestResource string) bool {
	for _, resource := range policyResources {
		if pe.matchResource(resource, requestResource) {
			return true
		}
	}
	return false
}

// matchResource matches a resource ARN pattern against a request resource ARN
func (pe *PolicyEvaluator) matchResource(pattern, resource string) bool {
	if pattern == "*" {
		return true
	}

	// Exact match
	if pattern == resource {
		return true
	}

	// Handle wildcards in the resource path
	// e.g., arn:nexus:s3:::images/* matches arn:nexus:s3:::images/photo.png
	if strings.Contains(pattern, "*") {
		return pe.globMatch(pattern, resource)
	}

	// Handle ? single char wildcard
	if strings.Contains(pattern, "?") {
		return pe.globMatch(pattern, resource)
	}

	return false
}

// globMatch performs simple glob matching with * and ?
func (pe *PolicyEvaluator) globMatch(pattern, str string) bool {
	pi, si := 0, 0
	starIdx := -1
	matchIdx := 0

	for si < len(str) {
		if pi < len(pattern) && (pattern[pi] == str[si] || pattern[pi] == '?') {
			pi++
			si++
		} else if pi < len(pattern) && pattern[pi] == '*' {
			starIdx = pi
			matchIdx = si
			pi++
		} else if starIdx != -1 {
			pi = starIdx + 1
			matchIdx++
			si = matchIdx
		} else {
			return false
		}
	}

	for pi < len(pattern) && pattern[pi] == '*' {
		pi++
	}

	return pi == len(pattern)
}

// principalMatches checks if the request principal matches the policy principal
func (pe *PolicyEvaluator) principalMatches(principal *Principal, requestPrincipal string) bool {
	// Check AWS principals
	for _, p := range principal.AWS {
		if p == "*" {
			return true
		}
		if p == requestPrincipal {
			return true
		}
		// Match user ARN
		if strings.HasPrefix(requestPrincipal, ARNPrefix) {
			if pe.globMatch(p, requestPrincipal) {
				return true
			}
		}
	}
	return len(principal.AWS) == 0 && len(principal.Service) == 0 && len(principal.Federated) == 0
}

// conditionsMatch evaluates condition blocks
func (pe *PolicyEvaluator) conditionsMatch(conditions map[string]map[string]interface{}, ctx *EvalContext) bool {
	for operator, conditionsByKey := range conditions {
		for key, expectedValue := range conditionsByKey {
			if !pe.conditionMatches(operator, key, expectedValue, ctx) {
				return false
			}
		}
	}
	return true
}

// conditionMatches evaluates a single condition
func (pe *PolicyEvaluator) conditionMatches(operator, key string, expectedValue interface{}, ctx *EvalContext) bool {
	// Get actual value from context
	var actualValue string
	switch strings.ToLower(key) {
	case "aws:sourceip":
		actualValue = ctx.SourceIP
	case "aws:currenttime":
		actualValue = ctx.Time.Format(time.RFC3339)
	default:
		if ctx.Conditions != nil {
			actualValue = ctx.Conditions[key]
		}
	}

	if actualValue == "" {
		return false
	}

	// Normalize expected value
	var expectedStr string
	switch v := expectedValue.(type) {
	case string:
		expectedStr = v
	case []interface{}:
		// For multi-value conditions, any match suffices
		for _, item := range v {
			if s, ok := item.(string); ok {
				if pe.compareValues(operator, actualValue, s) {
					return true
				}
			}
		}
		return false
	default:
		expectedStr = fmt.Sprintf("%v", v)
	}

	return pe.compareValues(operator, actualValue, expectedStr)
}

// compareValues compares actual vs expected using the condition operator
func (pe *PolicyEvaluator) compareValues(operator, actual, expected string) bool {
	switch strings.ToLower(operator) {
	case "stringequals", "stringlike":
		return pe.globMatch(expected, actual)
	case "stringnotequals":
		return !pe.globMatch(expected, actual)
	case "ipaddress":
		return pe.ipInRange(actual, expected)
	case "notipaddress":
		return !pe.ipInRange(actual, expected)
	case "datelessthan":
		return pe.dateLessThan(actual, expected)
	case "dategreaterthan":
		return !pe.dateLessThan(actual, expected)
	case "bool":
		return strings.ToLower(actual) == strings.ToLower(expected)
	default:
		return actual == expected
	}
}

// ipInRange checks if an IP is in a CIDR range (simplified)
func (pe *PolicyEvaluator) ipInRange(ip, cidr string) bool {
	// Simple prefix match for common cases
	if cidr == "*" {
		return true
	}
	if !strings.Contains(cidr, "/") {
		return ip == cidr
	}
	// For full CIDR support, use net.Contains
	// Simplified: just check prefix for now
	parts := strings.Split(cidr, "/")
	if len(parts) == 2 && parts[1] == "0" {
		return true // 0 means all IPs
	}
	return strings.HasPrefix(ip, strings.ReplaceAll(parts[0], "0", ""))
}

// dateLessThan checks if a date string is less than another
func (pe *PolicyEvaluator) dateLessThan(actual, expected string) bool {
	a, err1 := time.Parse(time.RFC3339, actual)
	b, err2 := time.Parse(time.RFC3339, expected)
	if err1 != nil || err2 != nil {
		return actual < expected
	}
	return a.Before(b)
}

// extractBucketFromResource extracts bucket name from an ARN resource
func extractBucketFromResource(resource string) string {
	// arn:nexus:s3:::bucket-name/key -> bucket-name
	// arn:nexus:s3:::bucket-name -> bucket-name
	if !strings.HasPrefix(resource, ARNPrefix+ServiceS3+":::") {
		return ""
	}
	rest := strings.TrimPrefix(resource, ARNPrefix+ServiceS3+":::")
	parts := strings.SplitN(rest, "/", 2)
	return parts[0]
}

// ParsePolicyDocument parses a JSON policy document
func ParsePolicyDocument(data []byte) (*PolicyDocument, error) {
	var doc PolicyDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("failed to parse policy document: %w", err)
	}
	return &doc, nil
}

// ParsePolicyDocumentFromString parses a JSON policy document from string
func ParsePolicyDocumentFromString(data string) (*PolicyDocument, error) {
	return ParsePolicyDocument([]byte(data))
}

// ResourceToS3Path converts an ARN resource to bucket/key
func ResourceToS3Path(resource string) (bucket, key string) {
	if !strings.HasPrefix(resource, ARNPrefix+ServiceS3+":::") {
		return "", ""
	}
	rest := strings.TrimPrefix(resource, ARNPrefix+ServiceS3+":::")
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) == 1 {
		return parts[0], ""
	}
	return parts[0], parts[1]
}

// S3PathToResource converts bucket/key to an ARN resource
func S3PathToResource(bucket, key string) string {
	if key == "" {
		return MakeBucketARN(bucket)
	}
	return MakeObjectARN(bucket, filepath.ToSlash(key))
}

// IsAdminAction checks if an action is an IAM/admin action
func IsAdminAction(action string) bool {
	return strings.HasPrefix(action, "iam:") || strings.HasPrefix(action, "sts:") || strings.HasPrefix(action, "admin:")
}
