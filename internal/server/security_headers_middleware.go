package server

import (
	"bufio"
	"errors"
	"net"
	"net/http"
)

const (
	// One year, plus subdomains, as recommended by the Intruder finding
	// (FBOT-4860). No `preload`: that is a one-way, browser-list commitment
	// that should be a deliberate decision, not a proxy default.
	securityHeaderHSTSValue           = "max-age=31536000; includeSubDomains"
	securityHeaderContentTypeOptions  = "nosniff"
	securityHeaderFrameOptions        = "SAMEORIGIN"
	securityHeaderReferrerPolicyValue = "strict-origin-when-cross-origin"
)

// SecurityHeadersMiddleware adds baseline HTTP security headers to every
// response the proxy sends, whether it came from an upstream target, from the
// router (404), from a redirect, or from an error page.
//
// Headers are applied at WriteHeader time and only when the upstream did not
// already set them, so applications keep full control (and there are no
// duplicates: httputil.ReverseProxy *adds* upstream headers, so pre-setting
// them on the ResponseWriter would double them).
//
// Strict-Transport-Security is only sent on TLS connections; browsers ignore it
// over plain HTTP anyway and the RFC says not to send it there.
type SecurityHeadersMiddleware struct {
	next http.Handler
}

func WithSecurityHeadersMiddleware(next http.Handler) http.Handler {
	return &SecurityHeadersMiddleware{next: next}
}

func (h *SecurityHeadersMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	writer := &securityHeadersResponseWriter{ResponseWriter: w, tls: r.TLS != nil}
	h.next.ServeHTTP(writer, r)
}

// applySecurityHeaders fills in the headers that are still missing.
func applySecurityHeaders(header http.Header, tls bool) {
	setIfMissing := func(name, value string) {
		if header.Get(name) == "" {
			header.Set(name, value)
		}
	}

	if tls {
		setIfMissing("Strict-Transport-Security", securityHeaderHSTSValue)
	}
	setIfMissing("X-Content-Type-Options", securityHeaderContentTypeOptions)
	setIfMissing("Referrer-Policy", securityHeaderReferrerPolicyValue)

	// A Content-Security-Policy with frame-ancestors supersedes X-Frame-Options;
	// if the app ships any CSP, leave framing policy to it.
	if header.Get("Content-Security-Policy") == "" {
		setIfMissing("X-Frame-Options", securityHeaderFrameOptions)
	}
}

type securityHeadersResponseWriter struct {
	http.ResponseWriter
	tls           bool
	headerWritten bool
}

func (w *securityHeadersResponseWriter) WriteHeader(statusCode int) {
	if !w.headerWritten {
		applySecurityHeaders(w.ResponseWriter.Header(), w.tls)
		w.headerWritten = true
	}
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *securityHeadersResponseWriter) Write(b []byte) (int, error) {
	if !w.headerWritten {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

func (w *securityHeadersResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("ResponseWriter does not implement http.Hijacker")
	}
	return hijacker.Hijack()
}

func (w *securityHeadersResponseWriter) Flush() {
	if !w.headerWritten {
		w.WriteHeader(http.StatusOK)
	}
	flusher, ok := w.ResponseWriter.(http.Flusher)
	if ok {
		flusher.Flush()
	}
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (w *securityHeadersResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}
