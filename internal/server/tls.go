package server

import "crypto/tls"

// tlsCipherSuites is the TLS 1.2 cipher suite allow-list for the public HTTPS
// listener. Only forward-secret AEAD suites are offered: no CBC/SHA-1, no RSA
// key exchange, no 3DES. TLS 1.3 suites are not configurable in Go and are
// always the modern AEAD set.
//
// Both ECDSA and RSA variants stay in the list because autocert issues an
// ECDSA P-256 certificate by default but falls back to RSA 2048 for clients that
// do not advertise ECDSA support.
var tlsCipherSuites = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
}

// newHTTPSTLSConfig builds the tls.Config used by the HTTPS listener: TLS 1.2 as
// the floor, the explicit cipher suite allow-list above, and modern key
// exchange curves.
func newHTTPSTLSConfig(getCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error), nextProtos []string) *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		CipherSuites: tlsCipherSuites,
		CurvePreferences: []tls.CurveID{
			tls.X25519MLKEM768,
			tls.X25519,
			tls.CurveP256,
			tls.CurveP384,
		},
		NextProtos:     nextProtos,
		GetCertificate: getCertificate,
	}
}
