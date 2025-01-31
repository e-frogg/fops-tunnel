package server

import (
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestMarshalPrivateKey(t *testing.T) {
	// Generate a test RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Marshal the private key
	keyData := marshalPrivateKey(privateKey)

	// Verify the key format
	if !strings.Contains(string(keyData), "-----BEGIN RSA PRIVATE KEY-----") {
		t.Error("Marshaled key does not contain RSA private key header")
	}
	if !strings.Contains(string(keyData), "-----END RSA PRIVATE KEY-----") {
		t.Error("Marshaled key does not contain RSA private key footer")
	}

	// Try to parse the key with ssh package
	signer, err := ssh.ParsePrivateKey(keyData)
	if err != nil {
		t.Fatalf("Failed to parse marshaled private key: %v", err)
	}

	// Verify the key type
	if signer.PublicKey().Type() != "ssh-rsa" {
		t.Errorf("Expected key type 'ssh-rsa', got '%s'", signer.PublicKey().Type())
	}
}
