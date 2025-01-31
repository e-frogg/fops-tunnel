package fopstunnel

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// setupTestServer creates a test SSH server for testing the client
func setupTestServer(t *testing.T) (string, int, func()) {
	// Generate server key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	config := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			return &ssh.Permissions{}, nil
		},
	}
	config.AddHostKey(signer)

	// Start SSH server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start test server: %v", err)
	}

	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("Failed to get server port: %v", err)
	}

	// Handle connections
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}

			go handleTestConnection(t, conn, config)
		}
	}()

	cleanup := func() {
		listener.Close()
	}

	return "127.0.0.1", parseInt(port), cleanup
}

func handleTestConnection(t *testing.T, conn net.Conn, config *ssh.ServerConfig) {
	defer conn.Close()

	// Perform SSH handshake
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		t.Logf("Failed SSH handshake: %v", err)
		return
	}
	defer sshConn.Close()

	go ssh.DiscardRequests(reqs)

	// Handle channels
	for newChannel := range chans {
		if newChannel.ChannelType() != "tunnel" {
			if err := newChannel.Reject(ssh.UnknownChannelType, "unknown channel type"); err != nil {
				t.Logf("Failed to reject channel: %v", err)
			}
			continue
		}

		channel, requests, err := newChannel.Accept()
		if err != nil {
			t.Logf("Failed to accept channel: %v", err)
			continue
		}

		go handleTestChannel(t, channel, requests)
	}
}

func handleTestChannel(t *testing.T, channel ssh.Channel, requests <-chan *ssh.Request) {
	defer channel.Close()

	for req := range requests {
		switch req.Type {
		case "tunnel-request":
			// Accept any tunnel request
			if err := req.Reply(true, nil); err != nil {
				t.Logf("Failed to reply to tunnel request: %v", err)
			}
		default:
			if err := req.Reply(false, nil); err != nil {
				t.Logf("Failed to reply to request: %v", err)
			}
		}
	}
}

func TestNewTunnelClient(t *testing.T) {
	client := NewTunnelClient("test.host", 2222, "test", "/path/to/key")

	if client.Host != "test.host" {
		t.Errorf("Expected host test.host, got %s", client.Host)
	}
	if client.Port != 2222 {
		t.Errorf("Expected port 2222, got %d", client.Port)
	}
	if client.User != "test" {
		t.Errorf("Expected user test, got %s", client.User)
	}
	if client.PrivateKeyPath != "/path/to/key" {
		t.Errorf("Expected key path /path/to/key, got %s", client.PrivateKeyPath)
	}
	if client.logger == nil {
		t.Error("Logger should not be nil")
	}
}

func TestTunnelClientConnect(t *testing.T) {
	// Generate test key pair
	privateKey, _ := generateTestKeyPair(t)

	// Create temporary key file
	keyFile := createTestKeyFile(t, privateKey)
	defer os.Remove(keyFile)

	// Start test server
	host, port, cleanup := setupTestServer(t)
	defer cleanup()

	// Create and test client
	client := NewTunnelClient(host, port, "test", keyFile)
	err := client.Connect()
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer client.Close()

	if client.sshClient == nil {
		t.Error("SSH client should not be nil after successful connection")
	}
}

func TestTunnelClientCreateTunnel(t *testing.T) {
	// Generate test key pair
	privateKey, _ := generateTestKeyPair(t)

	// Create temporary key file
	keyFile := createTestKeyFile(t, privateKey)
	defer os.Remove(keyFile)

	// Start test server
	host, port, cleanup := setupTestServer(t)
	defer cleanup()

	// Start a mock service to forward to
	mockService := startMockService(t)
	defer mockService.Close()

	// Get the mock service port
	_, mockPortStr, _ := net.SplitHostPort(mockService.Addr().String())
	mockPort := parseInt(mockPortStr)

	// Create and connect client
	client := NewTunnelClient(host, port, "test", keyFile)
	err := client.Connect()
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer client.Close()

	// Test creating tunnel
	err = client.CreateTunnel(mockPort, "test-tunnel")
	if err != nil {
		t.Fatalf("Failed to create tunnel: %v", err)
	}

	if client.sshChannel == nil {
		t.Error("SSH channel should not be nil after creating tunnel")
	}
}

func TestTunnelClientClose(t *testing.T) {
	// Generate test key pair
	privateKey, _ := generateTestKeyPair(t)

	// Create temporary key file
	keyFile := createTestKeyFile(t, privateKey)
	defer os.Remove(keyFile)

	// Start test server
	host, port, cleanup := setupTestServer(t)
	defer cleanup()

	// Start a mock service to forward to
	mockService := startMockService(t)
	defer mockService.Close()

	// Get the mock service port
	_, mockPortStr, _ := net.SplitHostPort(mockService.Addr().String())
	mockPort := parseInt(mockPortStr)

	// Create and connect client
	client := NewTunnelClient(host, port, "test", keyFile)
	err := client.Connect()
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}

	// Create tunnel
	err = client.CreateTunnel(mockPort, "test-tunnel")
	if err != nil {
		t.Fatalf("Failed to create tunnel: %v", err)
	}

	// Test closing
	err = client.Close()
	if err != nil {
		t.Fatalf("Failed to close client: %v", err)
	}

	if client.sshClient != nil {
		t.Error("SSH client should be nil after closing")
	}
	if client.sshChannel != nil {
		t.Error("SSH channel should be nil after closing")
	}
}

func TestTunnelClientRemoteHostForwarding(t *testing.T) {
	// Generate test key pair
	privateKey, _ := generateTestKeyPair(t)

	// Create temporary key file
	keyFile := createTestKeyFile(t, privateKey)
	defer os.Remove(keyFile)

	// Start test server
	host, port, cleanup := setupTestServer(t)
	defer cleanup()

	// Start a mock service to forward to
	mockService := startMockService(t)
	defer mockService.Close()

	// Get the mock service host and port
	mockHost, mockPortStr, _ := net.SplitHostPort(mockService.Addr().String())
	mockPort := parseInt(mockPortStr)

	// Create and connect client
	client := NewTunnelClient(host, port, "test", keyFile)
	err := client.Connect()
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer client.Close()

	// Test creating tunnel with remote host
	err = client.CreateTunnelWithRemoteHost(mockHost, mockPort, "test-tunnel")
	if err != nil {
		t.Fatalf("Failed to create tunnel with remote host: %v", err)
	}

	if client.sshChannel == nil {
		t.Error("SSH channel should not be nil after creating tunnel")
	}

	if client.TargetHost != mockHost {
		t.Errorf("Expected target host %s, got %s", mockHost, client.TargetHost)
	}
}

// Helper functions

func generateTestKeyPair(t *testing.T) ([]byte, []byte) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	// Convert private key to PEM format
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	// Generate public key
	publicKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to create public key: %v", err)
	}

	return privateKeyPEM, ssh.MarshalAuthorizedKey(publicKey)
}

func createTestKeyFile(t *testing.T, privateKeyPEM []byte) string {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "test_key")
	err := os.WriteFile(keyPath, privateKeyPEM, 0600)
	if err != nil {
		t.Fatalf("Failed to write test key file: %v", err)
	}
	return keyPath
}

func parseInt(s string) int {
	var n int
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil {
		panic(fmt.Sprintf("Failed to parse integer: %v", err))
	}
	return n
}

// Helper function to start a mock service
func startMockService(t *testing.T) net.Listener {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start mock service: %v", err)
	}

	// Handle connections in background
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close() // Just accept and close connections
		}
	}()

	return listener
}

// setupTestSSHAgent creates a test SSH agent with a test key
func setupTestSSHAgent(t *testing.T) (*agent.Agent, string) {
	// Create SSH agent
	testAgent := agent.NewKeyring()

	// Generate a test key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	// Add key to agent
	key := agent.AddedKey{
		PrivateKey: privateKey,
	}
	err = testAgent.Add(key)
	if err != nil {
		t.Fatalf("Failed to add key to agent: %v", err)
	}

	// Create temporary socket
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "agent.sock")

	return &testAgent, socketPath
}

func TestTunnelClientConnectWithAgent(t *testing.T) {
	// Setup test agent
	testAgent, socketPath := setupTestSSHAgent(t)

	// Create agent socket listener
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("Failed to create agent socket: %v", err)
	}
	defer listener.Close()

	// Créer un canal pour signaler l'arrêt
	done := make(chan struct{})
	defer close(done)

	// Handle agent connections in background
	go func() {
		for {
			select {
			case <-done:
				return
			default:
				conn, err := listener.Accept()
				if err != nil {
					select {
					case <-done:
						return
					default:
						t.Logf("Failed to accept connection: %v", err)
					}
					continue
				}
				go func(conn net.Conn) {
					defer conn.Close()
					if err := agent.ServeAgent(*testAgent, conn); err != nil {
						select {
						case <-done:
							return
						default:
							t.Logf("Failed to serve agent: %v", err)
						}
					}
				}(conn)
			}
		}
	}()

	// Set SSH_AUTH_SOCK environment variable
	os.Setenv("SSH_AUTH_SOCK", socketPath)
	defer os.Unsetenv("SSH_AUTH_SOCK")

	// Start test server
	host, port, cleanup := setupTestServer(t)
	defer cleanup()

	// Create and test client without private key
	client := NewTunnelClient(host, port, "test", "")
	err = client.Connect()
	if err != nil {
		t.Fatalf("Failed to connect with agent: %v", err)
	}
	defer client.Close()

	if client.sshClient == nil {
		t.Error("SSH client should not be nil after successful connection")
	}
}

func TestTunnelClientConnectWithAgentAndKey(t *testing.T) {
	// Setup test agent
	testAgent, socketPath := setupTestSSHAgent(t)

	// Create agent socket listener
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("Failed to create agent socket: %v", err)
	}
	defer listener.Close()

	// Créer un canal pour signaler l'arrêt
	done := make(chan struct{})
	defer close(done)

	// Handle agent connections in background
	go func() {
		for {
			select {
			case <-done:
				return
			default:
				conn, err := listener.Accept()
				if err != nil {
					select {
					case <-done:
						return
					default:
						t.Logf("Failed to accept connection: %v", err)
					}
					continue
				}
				go func(conn net.Conn) {
					defer conn.Close()
					if err := agent.ServeAgent(*testAgent, conn); err != nil {
						select {
						case <-done:
							return
						default:
							t.Logf("Failed to serve agent: %v", err)
						}
					}
				}(conn)
			}
		}
	}()

	// Set SSH_AUTH_SOCK environment variable
	os.Setenv("SSH_AUTH_SOCK", socketPath)
	defer os.Unsetenv("SSH_AUTH_SOCK")

	// Generate test key pair
	privateKey, _ := generateTestKeyPair(t)

	// Create temporary key file
	keyFile := createTestKeyFile(t, privateKey)
	defer os.Remove(keyFile)

	// Start test server
	host, port, cleanup := setupTestServer(t)
	defer cleanup()

	// Create and test client with both agent and private key
	client := NewTunnelClient(host, port, "test", keyFile)
	err = client.Connect()
	if err != nil {
		t.Fatalf("Failed to connect with agent and key: %v", err)
	}
	defer client.Close()

	if client.sshClient == nil {
		t.Error("SSH client should not be nil after successful connection")
	}
}

func TestTunnelClientConnectNoAuth(t *testing.T) {
	// Start test server
	host, port, cleanup := setupTestServer(t)
	defer cleanup()

	// Create client without any authentication method
	client := NewTunnelClient(host, port, "test", "")

	// Ensure SSH_AUTH_SOCK is not set
	os.Unsetenv("SSH_AUTH_SOCK")

	// Try to connect
	err := client.Connect()
	if err == nil {
		t.Error("Connect should fail when no authentication method is available")
	}
	if err.Error() != "no authentication methods available" {
		t.Errorf("Expected error 'no authentication methods available', got: %v", err)
	}
}
