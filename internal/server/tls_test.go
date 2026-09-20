package server

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHTTPSTLSConfig(t *testing.T) {
	config := newHTTPSTLSConfig(nil, []string{"h2", "http/1.1"})

	t.Run("requires at least TLS 1.2", func(t *testing.T) {
		assert.Equal(t, uint16(tls.VersionTLS12), config.MinVersion)
	})

	t.Run("keeps the ALPN protocols it was given", func(t *testing.T) {
		assert.Equal(t, []string{"h2", "http/1.1"}, config.NextProtos)
	})

	t.Run("offers only forward-secret AEAD suites", func(t *testing.T) {
		require.NotEmpty(t, config.CipherSuites)

		secure := map[uint16]*tls.CipherSuite{}
		for _, suite := range tls.CipherSuites() {
			secure[suite.ID] = suite
		}
		for _, suite := range tls.InsecureCipherSuites() {
			assert.NotContains(t, config.CipherSuites, suite.ID, "insecure suite %s must not be offered", suite.Name)
		}

		for _, id := range config.CipherSuites {
			suite, ok := secure[id]
			require.True(t, ok, "suite 0x%04x is not in Go's secure list", id)
			assert.True(t, strings.HasPrefix(suite.Name, "TLS_ECDHE_"), "%s is not forward secret", suite.Name)
			assert.NotContains(t, suite.Name, "_CBC_", "%s uses CBC", suite.Name)
			assert.NotContains(t, suite.Name, "3DES", "%s uses 3DES", suite.Name)
			assert.NotContains(t, suite.Name, "RC4", "%s uses RC4", suite.Name)
		}
	})
}

func TestHTTPSTLSConfig_Handshakes(t *testing.T) {
	// Stand up a real TLS server with the proxy's config (self-signed httptest
	// cert, RSA) and check what clients can and cannot negotiate.
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	server.TLS = newHTTPSTLSConfig(nil, []string{"http/1.1"})
	server.StartTLS()
	defer server.Close()

	connect := func(clientConfig *tls.Config) (*tls.Conn, error) {
		clientConfig.InsecureSkipVerify = true
		return tls.Dial("tcp", strings.TrimPrefix(server.URL, "https://"), clientConfig)
	}

	t.Run("rejects TLS 1.0 and TLS 1.1", func(t *testing.T) {
		for _, version := range []uint16{tls.VersionTLS10, tls.VersionTLS11} {
			conn, err := connect(&tls.Config{MinVersion: version, MaxVersion: version})
			if conn != nil {
				conn.Close()
			}
			assert.Error(t, err, "TLS version 0x%04x should be refused", version)
		}
	})

	t.Run("rejects a TLS 1.2 client that only offers CBC suites", func(t *testing.T) {
		conn, err := connect(&tls.Config{
			MinVersion:   tls.VersionTLS12,
			MaxVersion:   tls.VersionTLS12,
			CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA},
		})
		if conn != nil {
			conn.Close()
		}
		assert.Error(t, err)
	})

	t.Run("accepts a TLS 1.2 client offering an AEAD suite", func(t *testing.T) {
		conn, err := connect(&tls.Config{
			MinVersion:   tls.VersionTLS12,
			MaxVersion:   tls.VersionTLS12,
			CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		})
		require.NoError(t, err)
		defer conn.Close()

		assert.Equal(t, uint16(tls.VersionTLS12), conn.ConnectionState().Version)
		assert.Equal(t, uint16(tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256), conn.ConnectionState().CipherSuite)
	})

	t.Run("accepts TLS 1.3", func(t *testing.T) {
		conn, err := connect(&tls.Config{MinVersion: tls.VersionTLS13})
		require.NoError(t, err)
		defer conn.Close()

		assert.Equal(t, uint16(tls.VersionTLS13), conn.ConnectionState().Version)
	})
}
