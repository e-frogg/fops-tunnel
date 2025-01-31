package server

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
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
