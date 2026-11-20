package matchers

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func mustCompileCIDRMatcher(t *testing.T, condition string, cidrs ...string) *Matcher {
	t.Helper()
	matcher := &Matcher{
		Type:      MatcherTypeHolder{MatcherType: CIDRMatcher},
		Condition: condition,
		CIDR:      cidrs,
	}
	require.NoError(t, matcher.CompileMatchers())
	return matcher
}

func TestCIDRMatcherSingleIP(t *testing.T) {
	m := mustCompileCIDRMatcher(t, "", "10.0.0.0/8")

	isMatched, matched := m.MatchCIDR("10.1.2.3")
	require.True(t, isMatched, "Could not match IP inside the CIDR range")
	require.Equal(t, []string{"10.1.2.3"}, matched)

	isMatched, matched = m.MatchCIDR("192.168.1.1")
	require.False(t, isMatched, "Could match IP outside the CIDR range")
	require.Equal(t, []string{}, matched)
}

func TestCIDRMatcherIPv6(t *testing.T) {
	m := mustCompileCIDRMatcher(t, "", "fd00::/8")

	isMatched, _ := m.MatchCIDR("fd12:3456::1")
	require.True(t, isMatched, "Could not match IPv6 inside the CIDR range")

	isMatched, _ = m.MatchCIDR("2001:db8::1")
	require.False(t, isMatched, "Could match IPv6 outside the CIDR range")
}

func TestCIDRMatcherEmbeddedIP(t *testing.T) {
	m := mustCompileCIDRMatcher(t, "", "10.0.0.0/8")

	corpus := `{"version":4,"stratum":2,"ref_id":"10.1.2.3"}`
	isMatched, matched := m.MatchCIDR(corpus)
	require.True(t, isMatched, "Could not match IP embedded in a response corpus")
	require.Equal(t, []string{"10.1.2.3"}, matched)

	isMatched, _ = m.MatchCIDR(`{"ref_id":"GPS"}`)
	require.False(t, isMatched, "Could match corpus without any IP address")
}

func TestCIDRMatcherConditions(t *testing.T) {
	orMatcher := mustCompileCIDRMatcher(t, "or", "10.0.0.0/8", "192.168.0.0/16")
	isMatched, _ := orMatcher.MatchCIDR("192.168.0.10")
	require.True(t, isMatched, "Could not match valid cidr OR condition")

	isMatched, _ = orMatcher.MatchCIDR("172.16.0.1")
	require.False(t, isMatched, "Could match invalid cidr OR condition")

	andMatcher := mustCompileCIDRMatcher(t, "and", "10.0.0.0/8", "10.1.0.0/16")
	isMatched, _ = andMatcher.MatchCIDR("10.1.2.3")
	require.True(t, isMatched, "Could not match valid cidr AND condition")

	isMatched, _ = andMatcher.MatchCIDR("10.2.3.4")
	require.False(t, isMatched, "Could match invalid cidr AND condition")
}

func TestCIDRMatcherCompileErrors(t *testing.T) {
	matcher := &Matcher{
		Type: MatcherTypeHolder{MatcherType: CIDRMatcher},
		CIDR: []string{"not-a-cidr"},
	}
	require.Error(t, matcher.CompileMatchers(), "Invalid CIDR should fail compilation")

	empty := &Matcher{Type: MatcherTypeHolder{MatcherType: CIDRMatcher}}
	require.Error(t, empty.CompileMatchers(), "Missing cidr values should fail validation")

	unexpected := &Matcher{
		Type:  MatcherTypeHolder{MatcherType: CIDRMatcher},
		CIDR:  []string{"10.0.0.0/8"},
		Words: []string{"unexpected"},
	}
	require.Error(t, unexpected.CompileMatchers(), "Unexpected fields should fail validation")
}

func TestCIDRMatcherTypeString(t *testing.T) {
	require.Equal(t, "cidr", CIDRMatcher.String())
	require.Contains(t, GetSupportedMatcherTypes(), CIDRMatcher)
}
