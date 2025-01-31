package server

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

// TestTunnel wraps an SSH channel for testing
type TestTunnel struct {
	channel ssh.Channel
}

func (t *TestTunnel) Close() error {
	if t.channel != nil {
		return t.channel.Close()
	}
	return nil
}

func TestIntegrationTunnelCreationAndUsage(t *testing.T) {
	// Create SSH key pair for testing
	signer, err := generateTestSSHKey(t)
	if err != nil {
		t.Fatalf("Failed to generate SSH key: %v", err)
	}

	// Create temporary authorized_keys file
	authKeysPath, cleanup := createTempAuthKeysFile(t, signer.PublicKey())
	defer cleanup()

	// Initialize tunnel server
	ts := &TunnelServer{
		logger:         zap.NewExample(),
		SSHPort:        2222,
		AuthKeysPath:   authKeysPath,
		AllowedDomains: []string{"example.com"},
		Timeout:        500 * time.Millisecond,
		tunnels:        make(map[string]*Tunnel),
		portManager:    NewPortManager(10000, 20000),
		stopCleanup:    make(chan struct{}),
	}

	// Provision server
	ctx := caddy.Context{Context: context.Background()}
	if err := ts.Provision(ctx); err != nil {
		t.Fatalf("Failed to provision server: %v", err)
	}
	defer ts.Cleanup()

	// Create SSH client config with the same key
	config := &ssh.ClientConfig{
		User: "test",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	// Try to connect multiple times
	var client *ssh.Client
	for i := 0; i < 3; i++ {
		client, err = ssh.Dial("tcp", "localhost:2222", config)
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("Failed to connect to SSH server: %v", err)
	}
	defer client.Close()

	// Create tunnel
	tunnel, err := createTestTunnel(client, "test-tunnel")
	if err != nil {
		t.Fatalf("Failed to create tunnel: %v", err)
	}
	defer tunnel.Close()

	// Wait for tunnel to be established
	time.Sleep(50 * time.Millisecond)

	// Verify tunnel exists
	ts.mu.Lock()
	numTunnels := len(ts.tunnels)
	ts.mu.Unlock()

	if numTunnels != 1 {
		t.Errorf("Expected 1 tunnel after creation, got %d", numTunnels)
	}

	// Close tunnel and wait for cleanup
	tunnel.Close()
	time.Sleep(600 * time.Millisecond)

	// Verify tunnel is cleaned up
	ts.mu.Lock()
	numTunnels = len(ts.tunnels)
	ts.mu.Unlock()

	if numTunnels != 0 {
		t.Errorf("Expected 0 tunnels after cleanup, got %d", numTunnels)
	}
}

func TestIntegrationTunnelCleanup(t *testing.T) {
	// Create SSH key pair for testing
	signer, err := generateTestSSHKey(t)
	if err != nil {
		t.Fatalf("Failed to generate SSH key: %v", err)
	}

	// Create temporary authorized_keys file
	authKeysPath, cleanup := createTempAuthKeysFile(t, signer.PublicKey())
	defer cleanup()

	// Initialize tunnel server
	ts := &TunnelServer{
		logger:         zap.NewExample(),
		SSHPort:        2222,
		AuthKeysPath:   authKeysPath,
		AllowedDomains: []string{"example.com"},
		Timeout:        500 * time.Millisecond,
		tunnels:        make(map[string]*Tunnel),
		portManager:    NewPortManager(10000, 20000),
		stopCleanup:    make(chan struct{}),
	}

	// Provision server
	ctx := caddy.Context{Context: context.Background()}
	if err := ts.Provision(ctx); err != nil {
		t.Fatalf("Failed to provision server: %v", err)
	}
	defer ts.Cleanup()

	// Create SSH client config with the same key
	config := &ssh.ClientConfig{
		User: "test",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	// Try to connect multiple times
	var client *ssh.Client
	for i := 0; i < 3; i++ {
		client, err = ssh.Dial("tcp", "localhost:2222", config)
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("Failed to connect to SSH server: %v", err)
	}
	defer client.Close()

	// Create tunnel
	tunnel, err := createTestTunnel(client, "cleanup-test")
	if err != nil {
		t.Fatalf("Failed to create tunnel: %v", err)
	}
	defer tunnel.Close()

	// Wait for tunnel to be established
	time.Sleep(50 * time.Millisecond)

	// Verify tunnel exists
	ts.mu.Lock()
	numTunnels := len(ts.tunnels)
	ts.mu.Unlock()

	if numTunnels != 1 {
		t.Errorf("Expected 1 tunnel after creation, got %d", numTunnels)
	}

	// Close tunnel and wait for cleanup
	tunnel.Close()
	time.Sleep(600 * time.Millisecond)

	// Try to create a new tunnel with the same port
	newTunnel, err := createTestTunnel(client, "new-tunnel")
	if err != nil {
		t.Fatalf("Failed to create new tunnel: %v", err)
	}
	defer newTunnel.Close()

	// Verify new tunnel was created successfully
	if newTunnel == nil {
		t.Error("Expected new tunnel to be created after cleanup")
	}

	// Verify tunnel count
	ts.mu.Lock()
	numTunnels = len(ts.tunnels)
	ts.mu.Unlock()

	if numTunnels != 1 {
		t.Errorf("Expected 1 tunnel after new tunnel creation, got %d", numTunnels)
	}
}

// Helper function to create a test tunnel
func createTestTunnel(client *ssh.Client, subdomainSeed string) (*TestTunnel, error) {
	channel, requests, err := client.OpenChannel("tunnel", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to open tunnel channel: %v", err)
	}

	// Handle channel requests in background
	go ssh.DiscardRequests(requests)

	// Send tunnel request
	tunnelReq := TunnelRequest{
		TargetPort:    8080,
		TargetHost:    "localhost",
		SubdomainSeed: subdomainSeed,
	}

	ok, err := channel.SendRequest("tunnel-request", true, ssh.Marshal(tunnelReq))
	if err != nil || !ok {
		channel.Close()
		return nil, fmt.Errorf("failed to send tunnel request: %v", err)
	}

	return &TestTunnel{channel: channel}, nil
}
