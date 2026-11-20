//go:build integration
// +build integration

package integration_test

import (
	"net"
	"testing"
	"time"

	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
)

const ntpTestPacketSize = 48

// ntpTestServer is a minimal UDP NTP server answering with a stratum-2
// response whose reference id is the private address 10.1.2.3.
type ntpTestServer struct {
	URL  string
	conn *net.UDPConn
}

func newNTPTestServer(t *testing.T) *ntpTestServer {
	t.Helper()

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("could not start ntp test server: %v", err)
	}
	server := &ntpTestServer{URL: conn.LocalAddr().String(), conn: conn}

	go func() {
		buffer := make([]byte, ntpTestPacketSize)
		for {
			n, addr, err := conn.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			if n < ntpTestPacketSize {
				continue
			}
			_, _ = conn.WriteToUDP(ntpTestResponse(buffer[:n]), addr)
		}
	}()
	return server
}

func ntpTestResponse(request []byte) []byte {
	response := make([]byte, ntpTestPacketSize)
	response[0] = 0<<6 | 4<<3 | 4 // LI 0, version 4, mode server
	response[1] = 2               // stratum
	response[2] = 6               // poll
	response[3] = 0xEC            // precision
	copy(response[12:16], net.ParseIP("10.1.2.3").To4())
	copy(response[24:32], request[40:48]) // origin timestamp = client transmit
	seconds := uint32(time.Now().Unix() + 2208988800)
	for _, offset := range []int{32, 40} {
		response[offset] = byte(seconds >> 24)
		response[offset+1] = byte(seconds >> 16)
		response[offset+2] = byte(seconds >> 8)
		response[offset+3] = byte(seconds)
	}
	return response
}

func (s *ntpTestServer) Close() {
	_ = s.conn.Close()
}

func TestNTP(t *testing.T) {
	server := newNTPTestServer(t)
	defer server.Close()

	t.Run("Basic", func(t *testing.T) {
		results, err := testutils.RunNucleiTemplateAndGetResults("protocols/ntp/basic.yaml", server.URL, suite.debug)
		if err != nil {
			t.Fatalf("basic ntp request failed: %v", err)
		}
		if err := expectResultsCount(results, 1); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("CIDRMatcher", func(t *testing.T) {
		results, err := testutils.RunNucleiTemplateAndGetResults("protocols/ntp/cidr.yaml", server.URL, suite.debug)
		if err != nil {
			t.Fatalf("cidr ntp request failed: %v", err)
		}
		if err := expectResultsCount(results, 1); err != nil {
			t.Fatal(err)
		}
	})
}
