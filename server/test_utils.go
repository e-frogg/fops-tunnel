package server

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

// generateTestSSHKey generates an RSA key pair for testing
func generateTestSSHKey(t *testing.T) (ssh.Signer, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Convert to PEM format
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	// Parse the key into a signer
	signer, err := ssh.ParsePrivateKey(privateKeyPEM)
	if err != nil {
		t.Fatalf("Failed to parse private key: %v", err)
	}

	return signer, nil
}

// createTempAuthKeysFile creates a temporary authorized_keys file for testing
func createTempAuthKeysFile(t *testing.T, pubKey ssh.PublicKey) (string, func()) {
	// Create temp directory
	tempDir, err := os.MkdirTemp("", "ssh-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}

	// Create authorized_keys file
	authKeysPath := filepath.Join(tempDir, "authorized_keys")
	err = os.WriteFile(authKeysPath, ssh.MarshalAuthorizedKey(pubKey), 0600)
	if err != nil {
		os.RemoveAll(tempDir)
		t.Fatalf("Failed to write authorized_keys file: %v", err)
	}

	// Return cleanup function
	cleanup := func() {
		os.RemoveAll(tempDir)
	}

	return authKeysPath, cleanup
}

// marshalPrivateKey converts an RSA private key to PEM format
func marshalPrivateKey(key *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
}

// createTestSSHConfig creates an SSH client configuration for testing
func createTestSSHConfig(t *testing.T) (*ssh.ClientConfig, error) {
	// Generate a test key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	// Create signer
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create signer: %v", err)
	}

	// Create authorized_keys file
	authKeysDir := filepath.Join("testdata")
	err = os.MkdirAll(authKeysDir, 0755)
	if err != nil {
		return nil, fmt.Errorf("failed to create testdata directory: %v", err)
	}

	authKeysPath := filepath.Join(authKeysDir, "authorized_keys")
	authKeysFile, err := os.Create(authKeysPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create authorized_keys file: %v", err)
	}
	defer authKeysFile.Close()

	// Write public key to authorized_keys
	publicKey := ssh.MarshalAuthorizedKey(signer.PublicKey())
	_, err = authKeysFile.Write(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to write authorized_keys: %v", err)
	}

	// Create SSH client config
	config := &ssh.ClientConfig{
		User: "test",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	return config, nil
}

// createTestHTTPServer creates a test HTTP server for tunnel testing
func createTestHTTPServer(t *testing.T, port int) *http.Server {
	server := &http.Server{
		Addr: fmt.Sprintf(":%d", port),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("test response"))
		}),
	}

	go func() {
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			t.Logf("Test HTTP server error: %v", err)
		}
	}()

	return server
}
