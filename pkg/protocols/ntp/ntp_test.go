package ntp

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	templateTypes "github.com/projectdiscovery/nuclei/v3/pkg/templates/types"
)

// startTestNTPServer starts a UDP server answering NTP client requests with a
// stratum-2 secondary-server response referencing 10.1.2.3.
func startTestNTPServer(t *testing.T) string {
	t.Helper()

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	go func() {
		buffer := make([]byte, ntpPacketSize)
		for {
			n, addr, err := conn.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			if n < ntpPacketSize {
				continue
			}
			_, _ = conn.WriteToUDP(buildTestResponse(buffer[:n]), addr)
		}
	}()
	return conn.LocalAddr().String()
}

// buildTestResponse builds a valid mode-4 response echoing the request's
// transmit timestamp as origin timestamp.
func buildTestResponse(request []byte) []byte {
	response := make([]byte, ntpPacketSize)
	response[0] = byte(0<<6 | ntpVersion<<3 | 4) // server mode
	response[1] = 2                              // stratum
	response[2] = 6                              // poll
	response[3] = 0xEC                           // precision (-20)
	copy(response[12:16], net.ParseIP("10.1.2.3").To4())
	copy(response[24:32], request[40:48]) // origin timestamp = client transmit
	now := time.Now()
	putNTPTime(response[32:36], response[36:40], now)
	putNTPTime(response[40:44], response[44:48], now)
	return response
}

func runNTPRequest(t *testing.T, request *Request, input string) output.InternalEvent {
	t.Helper()

	options := testutils.DefaultOptions
	testutils.Init(options)

	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   "testing-ntp",
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	require.NoError(t, request.Compile(executerOpts))

	var gotEvent output.InternalEvent
	ctxArgs := contextargs.NewWithInput(context.Background(), input)
	err := request.ExecuteWithResults(ctxArgs, nil, nil, func(event *output.InternalWrappedEvent) {
		gotEvent = event.InternalEvent
	})
	require.NoError(t, err)
	require.NotEmpty(t, gotEvent)
	return gotEvent
}

func TestNTPRequest(t *testing.T) {
	address := startTestNTPServer(t)

	event := runNTPRequest(t, &Request{Address: address}, address)

	require.Equal(t, templateTypes.NTPProtocol.String(), event["type"])
	require.Equal(t, address, event["host"])
	require.Equal(t, 2, event["stratum"])
	require.Equal(t, ntpVersion, event["version"])
	require.Equal(t, "10.1.2.3", event["refid"])
	require.Contains(t, event["response"], `"stratum":2`)
	require.Contains(t, event["response"], `"ref_id":"10.1.2.3"`)
	require.NotEmpty(t, event["request"])

	duration, ok := event["duration"].(float64)
	require.True(t, ok, "expected duration to be a float64")
	require.GreaterOrEqual(t, duration, float64(0))
	require.Less(t, duration, float64(60))
}

func TestNTPRequestDefaultAddress(t *testing.T) {
	address := startTestNTPServer(t)

	// no address in the template: host and port come from the input variables
	event := runNTPRequest(t, &Request{}, address)
	require.Equal(t, address, event["host"])
	require.Equal(t, 2, event["stratum"])
}

func TestNTPMatchers(t *testing.T) {
	address := startTestNTPServer(t)

	request := &Request{Address: address}
	request.Operators.Matchers = []*matchers.Matcher{
		{
			Type:  matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher},
			Part:  "response",
			Words: []string{`"stratum":2`},
		},
		{
			Type: matchers.MatcherTypeHolder{MatcherType: matchers.DSLMatcher},
			DSL:  []string{`stratum == 2 && version == 4`},
		},
		{
			Type: matchers.MatcherTypeHolder{MatcherType: matchers.CIDRMatcher},
			Part: "refid",
			CIDR: []string{"10.0.0.0/8"},
		},
	}
	event := runNTPRequest(t, request, address)

	for _, matcher := range request.CompiledOperators.Matchers {
		matched, _ := request.Match(event, matcher)
		require.Truef(t, matched, "matcher %s should match", matcher.Type.String())
	}

	negative := &matchers.Matcher{
		Type: matchers.MatcherTypeHolder{MatcherType: matchers.CIDRMatcher},
		Part: "refid",
		CIDR: []string{"192.168.0.0/16"},
	}
	require.NoError(t, negative.CompileMatchers())
	matched, _ := request.Match(event, negative)
	require.False(t, matched, "cidr matcher should not match a different range")
}

func TestNTPSplitHostPort(t *testing.T) {
	host, port, err := splitHostPort("127.0.0.1:123")
	require.NoError(t, err)
	require.Equal(t, "127.0.0.1", host)
	require.Equal(t, "123", port)

	host, port, err = splitHostPort("example.com")
	require.NoError(t, err)
	require.Equal(t, "example.com", host)
	require.Empty(t, port)

	host, port, err = splitHostPort("[::1]:123")
	require.NoError(t, err)
	require.Equal(t, "::1", host)
	require.Equal(t, "123", port)

	host, port, err = splitHostPort("::1")
	require.NoError(t, err)
	require.Equal(t, "::1", host)
	require.Empty(t, port)
}

func TestNTPParseResponseErrors(t *testing.T) {
	_, err := parseResponse([]byte{1, 2, 3}, time.Now())
	require.Error(t, err, "short packets should be rejected")

	notServer := make([]byte, ntpPacketSize)
	notServer[0] = byte(0<<6 | ntpVersion<<3 | ntpModeClient)
	_, err = parseResponse(notServer, time.Now())
	require.Error(t, err, "client-mode packets should be rejected")
}

func TestNTPTypeAndParts(t *testing.T) {
	require.Equal(t, templateTypes.NTPProtocol, (&Request{}).Type())
	require.Equal(t, 1, (&Request{}).Requests())
	require.Equal(t, "ntp-id", (&Request{ID: "ntp-id"}).GetID())
	require.Contains(t, RequestPartDefinitions, "response")
	require.Contains(t, RequestPartDefinitions, "stratum")
	require.Contains(t, RequestPartDefinitions, "refid")
}
