package server

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/basecamp/kamal-proxy/internal/pages"
)

func TestSecurityHeadersMiddleware(t *testing.T) {
	serve := func(overTLS bool, handler http.HandlerFunc) *httptest.ResponseRecorder {
		middleware := WithSecurityHeadersMiddleware(handler)

		req := httptest.NewRequest("GET", "http://example.com", nil)
		if overTLS {
			req.TLS = &tls.ConnectionState{}
		}
		resp := httptest.NewRecorder()
		middleware.ServeHTTP(resp, req)
		return resp
	}

	upstreamOK := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("hello"))
	}

	t.Run("adds HSTS and baseline headers on TLS responses", func(t *testing.T) {
		resp := serve(true, upstreamOK)

		assert.Equal(t, http.StatusOK, resp.Code)
		assert.Equal(t, "max-age=31536000; includeSubDomains", resp.Header().Get("Strict-Transport-Security"))
		assert.Equal(t, "nosniff", resp.Header().Get("X-Content-Type-Options"))
		assert.Equal(t, "SAMEORIGIN", resp.Header().Get("X-Frame-Options"))
		assert.Equal(t, "strict-origin-when-cross-origin", resp.Header().Get("Referrer-Policy"))
	})

	t.Run("never sends HSTS over plain HTTP", func(t *testing.T) {
		resp := serve(false, upstreamOK)

		assert.Empty(t, resp.Header().Values("Strict-Transport-Security"))
		assert.Equal(t, "nosniff", resp.Header().Get("X-Content-Type-Options"))
	})

	t.Run("keeps headers the upstream already set, without duplicating them", func(t *testing.T) {
		resp := serve(true, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Strict-Transport-Security", "max-age=60")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("Referrer-Policy", "no-referrer")
			w.WriteHeader(http.StatusUnauthorized)
		})

		assert.Equal(t, http.StatusUnauthorized, resp.Code)
		assert.Equal(t, []string{"max-age=60"}, resp.Header().Values("Strict-Transport-Security"))
		assert.Equal(t, []string{"DENY"}, resp.Header().Values("X-Frame-Options"))
		assert.Equal(t, []string{"nosniff"}, resp.Header().Values("X-Content-Type-Options"))
		assert.Equal(t, []string{"no-referrer"}, resp.Header().Values("Referrer-Policy"))
	})

	t.Run("leaves framing to the app when it ships a Content-Security-Policy", func(t *testing.T) {
		resp := serve(true, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Security-Policy", "frame-ancestors 'self'")
			w.WriteHeader(http.StatusOK)
		})

		assert.Empty(t, resp.Header().Values("X-Frame-Options"))
		assert.Equal(t, "max-age=31536000; includeSubDomains", resp.Header().Get("Strict-Transport-Security"))
	})

	t.Run("applies to an implicit 200 written without WriteHeader", func(t *testing.T) {
		resp := serve(true, func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("implicit"))
		})

		assert.Equal(t, http.StatusOK, resp.Code)
		assert.Equal(t, "implicit", resp.Body.String())
		assert.Equal(t, "nosniff", resp.Header().Get("X-Content-Type-Options"))
	})

	t.Run("applies to proxy-generated error pages", func(t *testing.T) {
		errorHandler := func(w http.ResponseWriter, r *http.Request) {
			SetErrorResponse(w, r, http.StatusServiceUnavailable, nil)
		}
		withErrorPages, err := WithErrorPageMiddleware(pages.DefaultErrorPages, true, http.HandlerFunc(errorHandler))
		require.NoError(t, err)

		resp := serve(true, withErrorPages.ServeHTTP)

		assert.Equal(t, http.StatusServiceUnavailable, resp.Code)
		assert.Equal(t, "max-age=31536000; includeSubDomains", resp.Header().Get("Strict-Transport-Security"))
		assert.Equal(t, "nosniff", resp.Header().Get("X-Content-Type-Options"))
	})

	t.Run("applies to redirects", func(t *testing.T) {
		resp := serve(true, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://example.com/", http.StatusMovedPermanently)
		})

		assert.Equal(t, http.StatusMovedPermanently, resp.Code)
		assert.Equal(t, "max-age=31536000; includeSubDomains", resp.Header().Get("Strict-Transport-Security"))
	})
}
