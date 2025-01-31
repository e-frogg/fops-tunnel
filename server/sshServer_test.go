package server

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/crypto/ssh"
)

const testTimeout = 5 * time.Second

var testLogger *zap.Logger

func init() {
	config := zap.NewDevelopmentConfig()
	config.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	config.EncoderConfig.StacktraceKey = "" // Disable stacktrace
	config.EncoderConfig.TimeKey = "T"      // Shorter time key
	var err error
	testLogger, err = config.Build()
	if err != nil {
		panic(err)
	}
	testLogger.Info("Test logger initialized")
}

// waitForCondition waits for a condition to be true with timeout
func waitForCondition(t *testing.T, condition func() bool, message string) error {
	deadline := time.Now().Add(testTimeout)
	for time.Now().Before(deadline) {
		if condition() {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for %s", message)
}

// setupTestServer creates a test server with common configuration
func setupTestServer(t *testing.T, port int) (*SSHServer, *TunnelServer, ssh.Signer, func()) {
	testLogger.Info("Setting up test server", zap.Int("port", port))
	signer, err := generateTestSSHKey(t)
	if err != nil {
		t.Fatalf("Failed to generate SSH key: %v", err)
	}

	authKeysPath := writeAuthorizedKey(t, signer.PublicKey())

	ts := &TunnelServer{
		logger:         testLogger,
		SSHPort:        port,
		AuthKeysPath:   authKeysPath,
		AllowedDomains: []string{"localhost"},
		tunnels:        make(map[string]*Tunnel),
		portManager:    NewPortManager(port+1000, port+2000),
		stopCleanup:    make(chan struct{}),
	}

	server, err := NewSSHServer(ts)
	if err != nil {
		t.Fatalf("Failed to create SSH server: %v", err)
	}

	if err := server.Start(); err != nil {
		t.Fatalf("Failed to start SSH server: %v", err)
	}

	testLogger.Info("Test server started successfully")

	cleanup := func() {
		testLogger.Info("Cleaning up test server")
		close(ts.stopCleanup)
		server.Close()
		testLogger.Info("Test server cleanup completed")
	}

	return server, ts, signer, cleanup
}

// connectTestClient creates a test SSH client
func connectTestClient(t *testing.T, port int, signer ssh.Signer) *ssh.Client {
	config := &ssh.ClientConfig{
		User: "test",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         testTimeout,
	}

	client, err := ssh.Dial("tcp", fmt.Sprintf("localhost:%d", port), config)
	if err != nil {
		t.Fatalf("Failed to connect to SSH server: %v", err)
	}
	return client
}

func writeAuthorizedKey(t *testing.T, pubKey ssh.PublicKey) string {
	tempDir, err := os.MkdirTemp("", "ssh-test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}

	authKeysPath := filepath.Join(tempDir, "authorized_keys")
	authKeysContent := string(ssh.MarshalAuthorizedKey(pubKey))
	err = os.WriteFile(authKeysPath, []byte(authKeysContent), 0600)
	if err != nil {
		os.RemoveAll(tempDir)
		t.Fatalf("Failed to write authorized_keys file: %v", err)
	}

	t.Cleanup(func() {
		os.RemoveAll(tempDir)
	})

	return authKeysPath
}

func TestNewSSHServer(t *testing.T) {
	signer, err := generateTestSSHKey(t)
	if err != nil {
		t.Fatalf("Failed to generate SSH key: %v", err)
	}

	authKeysPath := writeAuthorizedKey(t, signer.PublicKey())

	ts := &TunnelServer{
		logger:       zap.NewExample(),
		SSHPort:      2222,
		AuthKeysPath: authKeysPath,
	}

	server, err := NewSSHServer(ts)
	if err != nil {
		t.Fatalf("Failed to create SSH server: %v", err)
	}

	if server.config == nil {
		t.Error("SSH server config was not initialized")
	}
}

func TestSSHServerStart(t *testing.T) {
	signer, err := generateTestSSHKey(t)
	if err != nil {
		t.Fatalf("Failed to generate SSH key: %v", err)
	}

	authKeysPath := writeAuthorizedKey(t, signer.PublicKey())

	ts := &TunnelServer{
		logger:       zap.NewExample(),
		SSHPort:      2222,
		AuthKeysPath: authKeysPath,
	}

	server, err := NewSSHServer(ts)
	if err != nil {
		t.Fatalf("Failed to create SSH server: %v", err)
	}

	err = server.Start()
	if err != nil {
		t.Fatalf("Failed to start SSH server: %v", err)
	}

	// Try to connect to the server
	config := &ssh.ClientConfig{
		User: "test",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	client, err := ssh.Dial("tcp", "localhost:2222", config)
	if err != nil {
		t.Fatalf("Failed to connect to SSH server: %v", err)
	}
	defer client.Close()
}

func TestHandleTunnelRequest(t *testing.T) {
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
		SSHPort:        2223,
		AuthKeysPath:   authKeysPath,
		AllowedDomains: []string{"localhost"},
		tunnels:        make(map[string]*Tunnel),
		portManager:    NewPortManager(10000, 20000),
		stopCleanup:    make(chan struct{}),
	}

	// Create SSH server
	server, err := NewSSHServer(ts)
	if err != nil {
		t.Fatalf("Failed to create SSH server: %v", err)
	}

	// Start SSH server
	if err := server.Start(); err != nil {
		t.Fatalf("Failed to start SSH server: %v", err)
	}

	// Create a WaitGroup to track all goroutines
	var wg sync.WaitGroup

	// Start a test HTTP server
	httpServer := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, err := fmt.Fprint(w, "test response"); err != nil {
				t.Errorf("Failed to write response: %v", err)
			}
		}),
	}

	// Create HTTP listener
	httpListener, err := net.Listen("tcp", ":8081")
	if err != nil {
		t.Fatalf("Failed to create HTTP listener: %v", err)
	}

	// Start HTTP server in a goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := httpServer.Serve(httpListener); err != nil && err != http.ErrServerClosed {
			t.Errorf("HTTP server error: %v", err)
		}
	}()

	// Ensure cleanup of all resources
	defer func() {
		// Shutdown HTTP server
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()

		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			t.Errorf("Failed to shutdown HTTP server: %v", err)
		}

		// Close SSH server
		if err := server.Close(); err != nil {
			t.Errorf("Failed to close SSH server: %v", err)
		}

		// Wait for all goroutines to complete
		done := make(chan struct{})
		go func() {
			wg.Wait()
			close(done)
		}()

		select {
		case <-done:
			t.Log("All goroutines completed")
		case <-time.After(5 * time.Second):
			t.Error("Timeout waiting for goroutines to complete")
		}
	}()

	// Connect to SSH server
	config := &ssh.ClientConfig{
		User: "test",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	client, err := ssh.Dial("tcp", fmt.Sprintf("localhost:%d", ts.SSHPort), config)
	if err != nil {
		t.Fatalf("Failed to connect to SSH server: %v", err)
	}
	defer client.Close()

	// Request tunnel
	t.Log("Sending tunnel request:", TunnelRequest{TargetPort: 8081, TargetHost: "localhost", SubdomainSeed: "test-tunnel"})
	channel, requests, err := client.OpenChannel("tunnel", nil)
	if err != nil {
		t.Fatalf("Failed to open tunnel channel: %v", err)
	}
	defer channel.Close()

	// Send tunnel request
	tunnelReq := TunnelRequest{
		TargetPort:    8081,
		TargetHost:    "localhost",
		SubdomainSeed: "test-tunnel",
	}
	ok, err := channel.SendRequest("tunnel-request", true, ssh.Marshal(tunnelReq))
	if err != nil {
		t.Fatalf("Failed to send tunnel request: %v", err)
	}
	if !ok {
		t.Fatal("Tunnel request was rejected")
	}

	go ssh.DiscardRequests(requests)

	// Wait for tunnel to be established
	time.Sleep(100 * time.Millisecond)

	// Verify tunnel exists
	ts.mu.RLock()
	var tunnel *Tunnel
	expectedSubdomain := "test-tunnel.localhost"
	for _, t := range ts.tunnels {
		if t.Subdomain == expectedSubdomain {
			tunnel = t
			break
		}
	}
	ts.mu.RUnlock()

	if tunnel == nil {
		t.Fatalf("Tunnel was not created with subdomain %s", expectedSubdomain)
	}

	// Test tunnel functionality
	resp, err := http.Get(fmt.Sprintf("http://localhost:%d/test", tunnel.RemotePort))
	if err != nil {
		t.Fatalf("Failed to make request through tunnel: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	if string(body) != "test response" {
		t.Errorf("Expected 'test response', got '%s'", string(body))
	}
}

func TestUnauthorizedSSHConnection(t *testing.T) {
	// Create an unauthorized key pair
	unauthorizedSigner, err := generateTestSSHKey(t)
	if err != nil {
		t.Fatalf("Failed to generate unauthorized SSH key: %v", err)
	}

	// Create authorized key pair
	authorizedSigner, err := generateTestSSHKey(t)
	if err != nil {
		t.Fatalf("Failed to generate authorized SSH key: %v", err)
	}

	// Create temporary authorized_keys file with only the authorized key
	authKeysPath := writeAuthorizedKey(t, authorizedSigner.PublicKey())

	// Initialize tunnel server
	ts := &TunnelServer{
		logger:       zap.NewExample(),
		SSHPort:      2224,
		AuthKeysPath: authKeysPath,
	}

	// Create and start SSH server
	server, err := NewSSHServer(ts)
	if err != nil {
		t.Fatalf("Failed to create SSH server: %v", err)
	}

	if err := server.Start(); err != nil {
		t.Fatalf("Failed to start SSH server: %v", err)
	}
	defer server.Close()

	// Try to connect with unauthorized key
	config := &ssh.ClientConfig{
		User: "test",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(unauthorizedSigner),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	_, err = ssh.Dial("tcp", fmt.Sprintf("localhost:%d", ts.SSHPort), config)
	if err == nil {
		t.Fatal("Expected connection to fail with unauthorized key, but it succeeded")
	}

	if !strings.Contains(err.Error(), "ssh: handshake failed") {
		t.Errorf("Expected handshake failure, got: %v", err)
	}
}

func TestTunnelConnectionError(t *testing.T) {
	// Setup log capture
	var buf safeBuffer
	core := zapcore.NewCore(
		zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()),
		zapcore.AddSync(&buf),
		zapcore.DebugLevel,
	)
	logger := zap.New(core)

	// Create SSH key pair for testing
	signer, err := generateTestSSHKey(t)
	if err != nil {
		t.Fatalf("Failed to generate test SSH key: %v", err)
	}

	// Create temporary authorized_keys file
	authKeysPath := writeAuthorizedKey(t, signer.PublicKey())

	// Create tunnel server with test configuration
	ts := &TunnelServer{
		logger:         logger,
		SSHPort:        2225,
		AuthKeysPath:   authKeysPath,
		AllowedDomains: []string{"localhost"},
		tunnels:        make(map[string]*Tunnel),
		portManager:    NewPortManager(20000, 30000),
		stopCleanup:    make(chan struct{}),
	}

	// Create and start SSH server
	server, err := NewSSHServer(ts)
	if err != nil {
		t.Fatalf("Failed to create SSH server: %v", err)
	}

	if err := server.Start(); err != nil {
		t.Fatalf("Failed to start SSH server: %v", err)
	}
	defer server.Close()

	// Connect to SSH server
	config := &ssh.ClientConfig{
		User: "test",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	client, err := ssh.Dial("tcp", fmt.Sprintf("localhost:%d", ts.SSHPort), config)
	if err != nil {
		t.Fatalf("Failed to connect to SSH server: %v", err)
	}
	defer client.Close()

	// Request tunnel to a non-existent port
	channel, requests, err := client.OpenChannel("tunnel", nil)
	if err != nil {
		t.Fatalf("Failed to open tunnel channel: %v", err)
	}
	defer channel.Close()

	// Send tunnel request to a port that's not listening
	tunnelReq := TunnelRequest{
		TargetPort:    54321, // Port that's not listening
		TargetHost:    "localhost",
		SubdomainSeed: "error-test",
	}
	ok, err := channel.SendRequest("tunnel-request", true, ssh.Marshal(tunnelReq))
	if err != nil {
		t.Fatalf("Failed to send tunnel request: %v", err)
	}
	if !ok {
		t.Fatal("Tunnel request was rejected")
	}

	go ssh.DiscardRequests(requests)

	// Wait for tunnel to be established
	time.Sleep(100 * time.Millisecond)

	// Try to connect through the tunnel
	conn, err := net.Dial("tcp", fmt.Sprintf("localhost:%d", ts.portManager.startPort))
	if err != nil {
		t.Fatal("Failed to connect to tunnel port:", err)
	}
	defer conn.Close()

	// Wait for error log
	time.Sleep(200 * time.Millisecond)

	// Verify that we get a connection refused error in the logs
	logOutput := buf.String()
	if !strings.Contains(logOutput, "connect: connection refused") {
		t.Error("Expected 'connection refused' error in logs, but got:", logOutput)
	}

	// Close the channel to trigger cleanup
	channel.Close()
	client.Close()

	// Force tunnel cleanup
	ts.mu.RLock()
	var tunnelID string
	for id := range ts.tunnels {
		tunnelID = id
		break
	}
	ts.mu.RUnlock()

	if tunnelID != "" {
		ts.removeTunnel(tunnelID)
	}

	// Verify that the tunnel is removed
	ts.mu.RLock()
	tunnelCount := len(ts.tunnels)
	ts.mu.RUnlock()
	if tunnelCount != 0 {
		t.Errorf("Expected all tunnels to be cleaned up, but found %d tunnels", tunnelCount)
	}
}

func TestServerCleanShutdown(t *testing.T) {
	defer traceTest(t)()
	testLogger.Info("Creating SSH key pair")

	signer, err := generateTestSSHKey(t)
	if err != nil {
		t.Fatalf("Failed to generate SSH key: %v", err)
	}

	testLogger.Info("Writing authorized keys file")
	authKeysPath := writeAuthorizedKey(t, signer.PublicKey())

	testLogger.Info("Initializing tunnel server")
	ts := &TunnelServer{
		logger:       testLogger,
		SSHPort:      2226,
		AuthKeysPath: authKeysPath,
	}

	testLogger.Info("Creating SSH server")
	server, err := NewSSHServer(ts)
	if err != nil {
		t.Fatalf("Failed to create SSH server: %v", err)
	}

	testLogger.Info("Starting SSH server")
	if err := server.Start(); err != nil {
		t.Fatalf("Failed to start SSH server: %v", err)
	}

	testLogger.Info("Creating SSH client config")
	config := &ssh.ClientConfig{
		User: "test",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	testLogger.Info("Attempting first SSH connection")
	client, err := ssh.Dial("tcp", fmt.Sprintf("localhost:%d", ts.SSHPort), config)
	if err != nil {
		t.Fatalf("Failed to connect to SSH server: %v", err)
	}

	testLogger.Info("First connection successful, closing server")
	if err := server.Close(); err != nil {
		t.Fatalf("Failed to close server: %v", err)
	}

	testLogger.Info("Server closed, attempting second connection (should fail)")
	_, err = ssh.Dial("tcp", fmt.Sprintf("localhost:%d", ts.SSHPort), config)
	if err == nil {
		t.Fatal("Expected connection to fail after server shutdown")
	}
	testLogger.Info("Second connection failed as expected", zap.Error(err))

	testLogger.Info("Closing client")
	client.Close()
}

func runWithTimeout(t *testing.T, name string, timeout time.Duration, f func(ctx context.Context) error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- f(ctx)
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("%s failed: %v", name, err)
		}
	case <-ctx.Done():
		t.Fatalf("%s timed out after %v", name, timeout)
	}
}

type safeBuffer struct {
	buffer bytes.Buffer
	mu     sync.Mutex
}

func (sb *safeBuffer) Write(p []byte) (n int, err error) {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	return sb.buffer.Write(p)
}

func (sb *safeBuffer) String() string {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	return sb.buffer.String()
}

func TestInteractiveSessionHandling(t *testing.T) {
	testLogger.Info("=== Starting test ===", zap.String("test", t.Name()))
	defer testLogger.Info("=== Ending test ===", zap.String("test", t.Name()))

	testLogger.Info("Starting interactive session test")

	testLogger.Info("Setting up test server")
	_, ts, signer, cleanup := setupTestServer(t, 2227)
	defer cleanup()

	runWithTimeout(t, "interactive session test", testTimeout, func(ctx context.Context) error {
		testLogger.Info("Connecting SSH client")
		client := connectTestClient(t, ts.SSHPort, signer)
		defer client.Close()

		testLogger.Info("Creating new session")
		session, err := client.NewSession()
		if err != nil {
			return fmt.Errorf("failed to create session: %v", err)
		}
		defer func() {
			testLogger.Info("Closing session")
			session.Close()
		}()

		sessionOutput := &safeBuffer{}
		session.Stdout = sessionOutput
		session.Stderr = sessionOutput

		testLogger.Info("Requesting shell")
		if err := session.Shell(); err != nil {
			return fmt.Errorf("failed to request shell: %v", err)
		}

		testLogger.Info("Waiting for shell response")
		responseDone := make(chan error, 1)
		go func() {
			defer close(responseDone)
			testLogger.Debug("Starting response wait")
			time.Sleep(100 * time.Millisecond)
			output := sessionOutput.String()
			testLogger.Debug("Got shell output", zap.String("output", output))
			expectedMessage := "Interactive shell is not supported"
			if !strings.Contains(output, expectedMessage) {
				responseDone <- fmt.Errorf("expected output to contain %q, got %q", expectedMessage, output)
				return
			}
			responseDone <- nil
		}()

		select {
		case err := <-responseDone:
			if err != nil {
				testLogger.Error("Shell response check failed", zap.Error(err))
				return err
			}
			testLogger.Info("Shell response verified successfully")
		case <-ctx.Done():
			testLogger.Error("Timeout waiting for shell response")
			return fmt.Errorf("timeout waiting for shell response")
		}

		return nil
	})
}

func TestTunnelPingHandling(t *testing.T) {
	testLogger.Info("Starting TestTunnelPingHandling")

	// Create a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	_, ts, signer, cleanup := setupTestServer(t, 2228)
	defer cleanup()

	// Create a WaitGroup to track all goroutines
	var wg sync.WaitGroup
	defer func() {
		testLogger.Info("Waiting for all goroutines to complete")
		done := make(chan struct{})
		go func() {
			wg.Wait()
			close(done)
		}()
		select {
		case <-done:
			testLogger.Info("All goroutines completed")
		case <-ctx.Done():
			testLogger.Error("Context cancelled while waiting for goroutines")
			t.Error("Context cancelled while waiting for goroutines")
		}
	}()

	testLogger.Info("Starting HTTP test server")
	httpDone := make(chan struct{})
	httpServer := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			testLogger.Debug("Received HTTP request", zap.String("path", r.URL.Path))
			fmt.Fprint(w, "test response")
		}),
	}

	httpListener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("Failed to start HTTP server: %v", err)
	}
	actualPort := httpListener.Addr().(*net.TCPAddr).Port
	testLogger.Info("HTTP server listening", zap.Int("port", actualPort))

	serverErrCh := make(chan error, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		testLogger.Debug("Starting HTTP server loop")
		if err := httpServer.Serve(httpListener); err != nil && err != http.ErrServerClosed {
			testLogger.Error("HTTP server error", zap.Error(err))
			serverErrCh <- err
		}
		testLogger.Debug("HTTP server loop ended")
		close(httpDone)
	}()

	defer func() {
		testLogger.Info("Starting HTTP server cleanup")
		if err := httpServer.Shutdown(ctx); err != nil {
			t.Errorf("Failed to shutdown HTTP server: %v", err)
		}
		httpListener.Close()
		select {
		case <-httpDone:
			testLogger.Info("HTTP server stopped cleanly")
		case <-ctx.Done():
			testLogger.Error("Timeout waiting for HTTP server to stop")
			t.Error("Timeout waiting for HTTP server to stop")
		}
	}()

	testLogger.Info("Connecting SSH client")
	client := connectTestClient(t, ts.SSHPort, signer)
	defer client.Close()

	testLogger.Info("Opening tunnel channel")
	channel, requests, err := client.OpenChannel("tunnel", nil)
	if err != nil {
		t.Fatalf("Failed to open tunnel channel: %v", err)
	}
	defer channel.Close()

	tunnelReq := TunnelRequest{
		TargetPort:    uint32(actualPort),
		TargetHost:    "localhost",
		SubdomainSeed: "ping-test",
	}
	testLogger.Info("Sending tunnel request",
		zap.Uint32("target_port", tunnelReq.TargetPort),
		zap.String("target_host", tunnelReq.TargetHost),
		zap.String("subdomain_seed", tunnelReq.SubdomainSeed))

	tunnelReqDone := make(chan error, 1)
	go func() {
		testLogger.Debug("Sending tunnel request")
		ok, err := channel.SendRequest("tunnel-request", true, ssh.Marshal(tunnelReq))
		if err != nil {
			testLogger.Error("Tunnel request failed", zap.Error(err))
			tunnelReqDone <- err
			return
		}
		if !ok {
			testLogger.Error("Tunnel request was rejected")
			tunnelReqDone <- fmt.Errorf("tunnel request was rejected")
			return
		}
		testLogger.Info("Tunnel request accepted")
		tunnelReqDone <- nil
	}()

	select {
	case err := <-tunnelReqDone:
		if err != nil {
			t.Fatalf("Failed to establish tunnel: %v", err)
		}
		testLogger.Info("Tunnel request completed successfully")
	case <-time.After(testTimeout):
		testLogger.Error("Timeout waiting for tunnel establishment")
		t.Fatal("Timeout waiting for tunnel establishment")
	}

	testLogger.Debug("Starting request discarder")
	go ssh.DiscardRequests(requests)

	testLogger.Info("Waiting for tunnel to be established")
	err = waitForCondition(t, func() bool {
		ts.mu.RLock()
		defer ts.mu.RUnlock()
		for _, tunnel := range ts.tunnels {
			if tunnel.Subdomain == "ping-test.localhost" {
				testLogger.Debug("Found matching tunnel",
					zap.String("subdomain", tunnel.Subdomain),
					zap.Int("remote_port", tunnel.RemotePort))
				return true
			}
		}
		return false
	}, "tunnel to be established")

	if err != nil {
		testLogger.Error("Tunnel establishment failed", zap.Error(err))
		t.Fatalf("Tunnel was not established: %v", err)
	}
	testLogger.Info("Tunnel established successfully")

	testLogger.Info("Sending ping request")
	pingDone := make(chan error, 1)
	go func() {
		testLogger.Debug("Sending ping request")
		ok, err := channel.SendRequest("ping", true, nil)
		if err != nil {
			testLogger.Error("Ping request failed", zap.Error(err))
			pingDone <- err
			return
		}
		if !ok {
			testLogger.Error("Ping request was rejected")
			pingDone <- fmt.Errorf("ping request was rejected")
			return
		}
		testLogger.Info("Ping request successful")
		pingDone <- nil
	}()

	select {
	case err := <-pingDone:
		if err != nil {
			t.Fatalf("Ping failed: %v", err)
		}
		testLogger.Info("First ping completed successfully")
	case <-time.After(testTimeout):
		testLogger.Error("Timeout waiting for ping response")
		t.Fatal("Timeout waiting for ping response")
	}

	testLogger.Info("Stopping HTTP server")
	if err := httpServer.Close(); err != nil {
		testLogger.Error("Failed to close HTTP server", zap.Error(err))
		t.Errorf("Failed to close HTTP server: %v", err)
	}

	testLogger.Info("Waiting for HTTP server to stop")
	select {
	case <-httpDone:
		testLogger.Info("HTTP server stopped")
	case err := <-serverErrCh:
		testLogger.Error("HTTP server error", zap.Error(err))
		t.Errorf("HTTP server error: %v", err)
	case <-time.After(testTimeout):
		testLogger.Error("Timeout waiting for HTTP server to stop")
		t.Error("Timeout waiting for HTTP server to stop")
	}

	testLogger.Info("Waiting for target to become inaccessible")
	time.Sleep(100 * time.Millisecond)

	testLogger.Info("Sending second ping request (should fail)")
	pingDone = make(chan error, 1)
	go func() {
		testLogger.Debug("Sending second ping request")
		ok, err := channel.SendRequest("ping", true, nil)
		if err != nil {
			testLogger.Error("Second ping request failed", zap.Error(err))
			pingDone <- err
			return
		}
		if ok {
			testLogger.Error("Second ping request unexpectedly succeeded")
			pingDone <- fmt.Errorf("ping request should have been rejected")
			return
		}
		testLogger.Info("Second ping request was rejected as expected")
		pingDone <- nil
	}()

	select {
	case err := <-pingDone:
		if err != nil {
			t.Fatalf("Unexpected ping result: %v", err)
		}
		testLogger.Info("Second ping completed as expected")
	case <-time.After(testTimeout):
		testLogger.Error("Timeout waiting for second ping response")
		t.Fatal("Timeout waiting for ping response")
	}

	testLogger.Info("TestTunnelPingHandling completed successfully")
}

// Add this helper function for test tracing
func traceTest(t *testing.T) func() {
	name := t.Name()
	testLogger.Info("=== Starting test ===", zap.String("test", name))
	return func() {
		testLogger.Info("=== Ending test ===", zap.String("test", name))
	}
}
