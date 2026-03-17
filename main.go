// A static file server that serves a directory over HTTP and optionally HTTPS.
//
// Usage examples:
//
//	go run main.go -dir ./public
//	go run main.go -dir ./public -http-port 9000
//	go run main.go -dir ./public -self-signed
//	go run main.go -dir ./public -cert server.crt -key server.key
//	go run main.go -dir ./public -http-port 9000 -https-port 9443 -cert server.crt -key server.key
package main

import (
	"crypto/ecdsa"       // Elliptic Curve Digital Signature Algorithm — for generating the private key
	"crypto/elliptic"    // Defines the elliptic curves used by ECDSA
	"crypto/rand"        // Cryptographically secure random number generator
	"crypto/tls"         // TLS (HTTPS) configuration and helpers
	"crypto/x509"        // X.509 certificate parsing and creation
	"crypto/x509/pkix"   // X.509 certificate subject/issuer name fields
	"encoding/pem"       // PEM encoding (the -----BEGIN CERTIFICATE----- format)
	"flag"               // Parses command-line flags (arguments like -dir ./public)
	"fmt"                // Formatted I/O — Sprintf, Printf, etc.
	"log"                // Logging with automatic timestamps
	"math/big"           // Arbitrary-precision integers (used for certificate serial numbers)
	"net"                // Network primitives — we use net.Listen to bind a port
	"net/http"           // HTTP client and server — the core of this program
	"os"                 // OS-level operations: file info, environment, signals
	"os/signal"          // Subscribes to OS signals so we can shut down cleanly
	"path/filepath"      // Cross-platform file path helpers
	"syscall"            // Low-level OS constants (signal types)
	"time"               // Time and duration — used for certificate validity period
)

func main() {
	// --- Parse command-line flags ---
	//
	// flag.String and flag.Int register a flag and return a *pointer*.
	// In Go, a pointer (*string, *int) holds the memory address of a value.
	// You read the actual value through the pointer with the * operator,
	// e.g. *httpPort gives you the int value 8080.
	dir        := flag.String("dir", ".", "Directory to serve (default: current directory)")
	httpPort   := flag.Int("http-port", 8080, "HTTP listen port")
	httpsPort  := flag.Int("https-port", 8443, "HTTPS listen port (requires -cert/-key or -self-signed)")
	certFile   := flag.String("cert", "", "Path to TLS certificate file (enables HTTPS)")
	keyFile    := flag.String("key", "", "Path to TLS private key file (requires -cert)")
	selfSigned := flag.Bool("self-signed", false, "Auto-generate a self-signed certificate for HTTPS")

	// Parse() reads os.Args and fills in the flag values defined above.
	flag.Parse()

	// Validate: -cert/-key must be provided together, and can't combine with -self-signed.
	if (*certFile == "") != (*keyFile == "") {
		log.Fatal("Both -cert and -key must be provided together to enable HTTPS")
	}
	if *selfSigned && *certFile != "" {
		log.Fatal("Cannot use -self-signed together with -cert/-key")
	}

	// --- Validate the target directory ---

	// filepath.Abs converts a relative path to absolute (e.g. "." → "/home/user/public").
	absDir, err := filepath.Abs(*dir)
	// Go convention: functions return (result, error). Always check err before using result.
	if err != nil {
		log.Fatalf("Failed to resolve directory path: %v", err)
	}

	// os.Stat returns metadata about a file or directory. We verify the path
	// exists and is actually a directory, not a regular file.
	info, err := os.Stat(absDir)
	if err != nil {
		log.Fatalf("Cannot access directory: %v", err)
	}
	if !info.IsDir() {
		log.Fatalf("Path is not a directory: %s", absDir)
	}

	// --- Build the request handler ---
	//
	// http.Handler is an *interface* — a contract that says "I have a ServeHTTP method."
	// http.FileServer returns a Handler that serves files from a directory.
	// http.Dir adapts a filesystem path into the interface that FileServer expects.
	fileServer := http.FileServer(http.Dir(absDir))

	// Wrap the file server with middleware for security headers and request logging.
	// Each middleware takes a Handler and returns a new Handler that adds behavior
	// before delegating to the original. This is a common Go pattern.
	handler := withLogging(withSecurityHeaders(fileServer))

	// --- Start HTTP server ---
	//
	// The "go" keyword launches a function in a *goroutine* — a lightweight
	// concurrent thread managed by the Go runtime. This lets us run the HTTP
	// and HTTPS servers at the same time without blocking each other.
	go func() {
		addr := fmt.Sprintf(":%d", *httpPort)
		log.Printf("Serving %s over HTTP on %s", absDir, addr)

		// ListenAndServe blocks forever, accepting connections.
		// It only returns on error (e.g. port already in use).
		if err := http.ListenAndServe(addr, handler); err != nil {
			log.Fatalf("HTTP server failed: %v", err)
		}
	}()

	// --- Start HTTPS server (if certs provided or self-signed requested) ---

	if *certFile != "" {
		// Use certificate files from disk.
		go func() {
			addr := fmt.Sprintf(":%d", *httpsPort)
			log.Printf("Serving %s over HTTPS on %s", absDir, addr)

			// ListenAndServeTLS loads the certificate and key files, configures
			// TLS, and serves HTTPS. Go's crypto/tls handles the handshake,
			// cipher negotiation, and encryption automatically.
			if err := http.ListenAndServeTLS(addr, *certFile, *keyFile, handler); err != nil {
				log.Fatalf("HTTPS server failed: %v", err)
			}
		}()
	} else if *selfSigned {
		// Generate a self-signed certificate in memory (nothing written to disk).
		go func() {
			tlsCert, err := generateSelfSignedCert()
			if err != nil {
				log.Fatalf("Failed to generate self-signed certificate: %v", err)
			}

			// tls.Config holds TLS settings for the server. Here we supply the
			// certificate directly instead of loading it from files.
			tlsConfig := &tls.Config{
				Certificates: []tls.Certificate{tlsCert},
			}

			addr := fmt.Sprintf(":%d", *httpsPort)
			log.Printf("Serving %s over HTTPS on %s (self-signed certificate)", absDir, addr)

			// Instead of http.ListenAndServeTLS (which reads cert files), we
			// manually create a TLS listener with our in-memory certificate,
			// then hand it to http.Serve.
			listener, err := tls.Listen("tcp", addr, tlsConfig)
			if err != nil {
				log.Fatalf("HTTPS server failed to listen: %v", err)
			}
			if err := http.Serve(listener, handler); err != nil {
				log.Fatalf("HTTPS server failed: %v", err)
			}
		}()
	}

	// --- Wait for shutdown signal ---
	//
	// The servers run in goroutines (background). If main() returns, the entire
	// program exits immediately — goroutines don't keep the process alive.
	//
	// A *channel* (chan) is Go's primary tool for communication between goroutines.
	// Here we create a channel that carries os.Signal values, subscribe it to
	// interrupt (Ctrl+C) and terminate signals, then block until one arrives.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit // ← blocks here until a signal is received
	log.Println("Shutting down.")
}

// --- Middleware ---
//
// Middleware functions follow a pattern: take an http.Handler, return a new
// http.Handler that wraps the original with additional behavior.
//
// http.HandlerFunc is an adapter that lets an ordinary function be used as
// an http.Handler. The function must have the signature:
//   func(http.ResponseWriter, *http.Request)
//
// - http.ResponseWriter: used to build and send the HTTP response
// - *http.Request: contains everything about the incoming request

// withLogging logs the remote address, HTTP method, and path of every request.
func withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s %s", r.RemoteAddr, r.Method, r.URL.Path)
		// Delegate to the wrapped handler to actually serve the response.
		next.ServeHTTP(w, r)
	})
}

// withSecurityHeaders adds protective HTTP headers to every response.
func withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Prevent browsers from guessing (MIME-sniffing) the content type,
		// which can be exploited to execute malicious files as scripts.
		w.Header().Set("X-Content-Type-Options", "nosniff")
		// Prevent the page from being embedded in an iframe on another site,
		// which defends against clickjacking attacks.
		w.Header().Set("X-Frame-Options", "DENY")

		next.ServeHTTP(w, r)
	})
}

// --- Self-signed certificate generation ---

// generateSelfSignedCert creates an in-memory TLS certificate valid for localhost.
// The certificate uses ECDSA with the P-256 curve, which is fast and widely supported.
// It is valid for 1 year from the time of generation.
//
// This returns a tls.Certificate, which bundles the public certificate and
// private key together — exactly what tls.Config.Certificates expects.
func generateSelfSignedCert() (tls.Certificate, error) {
	// Generate an ECDSA private key using the P-256 curve.
	// crypto/rand.Reader is a cryptographically secure random source.
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generating private key: %w", err)
	}

	// Define the certificate's properties using an x509.Certificate template.
	// A "template" in Go's x509 package is a struct whose fields describe
	// what the final certificate should look like.
	template := x509.Certificate{
		// SerialNumber uniquely identifies this certificate. For self-signed
		// certs, any unique number works. We use a large random value.
		SerialNumber: big.NewInt(1),
		// Subject is the identity on the certificate (who it belongs to).
		Subject: pkix.Name{
			Organization: []string{"Self-Signed"},
		},
		// Validity window.
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),

		// KeyUsage and ExtKeyUsage declare what this certificate is allowed to do.
		// DigitalSignature: can sign data (needed for TLS handshakes).
		// KeyEncipherment: can encrypt symmetric keys (needed for some TLS cipher suites).
		// CertSign: can sign certificates (needed because a self-signed cert is its own CA).
		// ExtKeyUsageServerAuth: this cert can be used by a TLS server.
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},

		// BasicConstraints identifies whether this certificate is a CA (Certificate
		// Authority). A self-signed certificate signs itself, so it is technically
		// a CA. Firefox requires this extension to be present before it will offer
		// the "Accept the Risk and Continue" option.
		BasicConstraintsValid: true,
		IsCA:                  true,

		// SAN (Subject Alternative Name) entries — the hostnames and IPs this
		// certificate is valid for. Browsers check these, not the Subject field.
		DNSNames:    []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	// x509.CreateCertificate generates the DER-encoded certificate bytes.
	// We pass the template as both "template" and "parent" because this is
	// self-signed — the certificate signs itself (it is its own parent).
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("creating certificate: %w", err)
	}

	// Encode the certificate and key into PEM format (the standard text format
	// for certificates, with -----BEGIN CERTIFICATE----- headers).
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	// x509.MarshalECPrivateKey converts the private key to DER format,
	// then we PEM-encode it.
	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("marshaling private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	// tls.X509KeyPair parses the PEM-encoded certificate and key into a
	// tls.Certificate that Go's TLS server can use directly.
	return tls.X509KeyPair(certPEM, keyPEM)
}
