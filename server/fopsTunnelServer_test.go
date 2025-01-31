package server

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func TestTunnelServerProvision(t *testing.T) {
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
		Timeout:        100 * time.Millisecond,
		tunnels:        make(map[string]*Tunnel),
		portManager:    NewPortManager(10000, 20000),
		stopCleanup:    make(chan struct{}),
	}

	// Test Provision method
	ctx := caddy.Context{
		Context: context.Background(),
	}
	if err := ts.Provision(ctx); err != nil {
		t.Fatalf("Failed to provision TunnelServer: %v", err)
	}

	// Cleanup
	ts.Cleanup()
}

func TestTunnelServerCleanup(t *testing.T) {
	// Create SSH key pair for testing
	signer, err := generateTestSSHKey(t)
	if err != nil {
		t.Fatalf("Failed to generate SSH key: %v", err)
	}

	// Create temporary authorized_keys file
	authKeysPath, cleanup := createTempAuthKeysFile(t, signer.PublicKey())
	defer cleanup()

	// Initialize tunnel server with longer timeout
	ts := &TunnelServer{
		logger:         zap.NewExample(),
		SSHPort:        2222,
		AuthKeysPath:   authKeysPath,
		AllowedDomains: []string{"example.com"},
		Timeout:        500 * time.Millisecond, // Longer timeout
		tunnels:        make(map[string]*Tunnel),
		portManager:    NewPortManager(10000, 20000),
		stopCleanup:    make(chan struct{}),
	}

	// Provision server
	ctx := caddy.Context{
		Context: context.Background(),
	}
	if err := ts.Provision(ctx); err != nil {
		t.Fatalf("Failed to provision server: %v", err)
	}

	// Create test tunnels with mock listeners
	tunnel1 := &Tunnel{
		ID:             "test1",
		Subdomain:      "test1.example.com",
		LocalPort:      8080,
		CreatedAt:      time.Now(),
		LastActive:     time.Now(),
		stopForwarding: make(chan struct{}),
	}

	tunnel2 := &Tunnel{
		ID:             "test2",
		Subdomain:      "test2.example.com",
		LocalPort:      8081,
		CreatedAt:      time.Now(),
		LastActive:     time.Now(),
		stopForwarding: make(chan struct{}),
	}

	// Allocate ports and add tunnels to server
	port1, err := ts.portManager.AllocatePort()
	if err != nil {
		t.Fatalf("Failed to allocate port1: %v", err)
	}
	tunnel1.RemotePort = port1

	port2, err := ts.portManager.AllocatePort()
	if err != nil {
		t.Fatalf("Failed to allocate port2: %v", err)
	}
	tunnel2.RemotePort = port2

	// Add tunnels to server
	ts.mu.Lock()
	ts.tunnels[tunnel1.ID] = tunnel1
	ts.tunnels[tunnel2.ID] = tunnel2
	ts.mu.Unlock()

	// Verify initial state
	ts.mu.Lock()
	numTunnelsBeforeCleanup := len(ts.tunnels)
	ts.mu.Unlock()

	if numTunnelsBeforeCleanup != 2 {
		t.Errorf("Expected 2 tunnels before cleanup, got %d", numTunnelsBeforeCleanup)
	}

	// Start cleanup routine
	go ts.cleanupRoutine()

	// Update tunnel2's LastActive to make it expire
	time.Sleep(100 * time.Millisecond)
	tunnel2.LastActive = time.Now().Add(-600 * time.Millisecond)

	// Keep tunnel1 active while waiting for cleanup
	done := make(chan bool)
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				tunnel1.LastActive = time.Now()
			}
		}
	}()

	// Wait for cleanup to process expired tunnel
	time.Sleep(600 * time.Millisecond)
	close(done)

	// Verify tunnels state after cleanup
	ts.mu.Lock()
	numTunnels := len(ts.tunnels)
	hasExpiredTunnel := false
	for _, t := range ts.tunnels {
		if t.ID == tunnel2.ID {
			hasExpiredTunnel = true
			break
		}
	}
	ts.mu.Unlock()

	if numTunnels != 1 {
		t.Errorf("Expected 1 tunnel after cleanup (only active tunnel), got %d", numTunnels)
	}

	if hasExpiredTunnel {
		t.Error("Expected expired tunnel to be removed, but it still exists")
	}

	// Verify port of expired tunnel is released
	if !ts.portManager.IsPortAvailable(port2) {
		t.Errorf("Expected port %d of expired tunnel to be available after cleanup", port2)
	}

	// Verify port of active tunnel is still in use
	if ts.portManager.IsPortAvailable(port1) {
		t.Errorf("Expected port %d of active tunnel to still be in use", port1)
	}

	// Stop cleanup routine
	close(ts.stopCleanup)

	// Cleanup
	ts.Cleanup()
}

func TestTunnelServerConcurrency(t *testing.T) {
	ts := &TunnelServer{
		logger:         zap.NewExample(),
		tunnels:        make(map[string]*Tunnel),
		portManager:    NewPortManager(10000, 20000),
		AllowedDomains: []string{"localhost"},
		Timeout:        5 * time.Second,
	}

	// Test concurrent tunnel creation and cleanup
	const numConcurrent = 10
	done := make(chan bool)

	for i := 0; i < numConcurrent; i++ {
		go func(id int) {
			tunnel := &Tunnel{
				ID:         generateID(),
				Subdomain:  fmt.Sprintf("test-%d.localhost", id),
				LocalPort:  8080 + id,
				RemotePort: 10000 + id,
				CreatedAt:  time.Now(),
				LastActive: time.Now(),
			}

			// Add tunnel
			ts.mu.Lock()
			ts.tunnels[tunnel.ID] = tunnel
			ts.mu.Unlock()

			// Simulate some activity
			time.Sleep(100 * time.Millisecond)

			// Update last active
			ts.mu.Lock()
			tunnel.LastActive = time.Now()
			ts.mu.Unlock()

			done <- true
		}(i)
	}

	// Wait for all goroutines to finish
	for i := 0; i < numConcurrent; i++ {
		<-done
	}

	// Verify final state
	ts.mu.Lock()
	numTunnels := len(ts.tunnels)
	ts.mu.Unlock()

	if numTunnels != numConcurrent {
		t.Errorf("Expected %d tunnels, got %d", numConcurrent, numTunnels)
	}
}

func TestTunnelServerPortExhaustion(t *testing.T) {
	// Create a port manager with a very small range
	ts := &TunnelServer{
		logger:      zap.NewExample(),
		tunnels:     make(map[string]*Tunnel),
		portManager: NewPortManager(10000, 10001), // Only 2 ports available
	}

	// Try to allocate more ports than available
	for i := 0; i < 3; i++ {
		tunnel := &Tunnel{
			ID:        generateID(),
			Subdomain: fmt.Sprintf("test%d.example.com", i),
			LocalPort: 8080 + i,
		}

		port, err := ts.portManager.AllocatePort()
		if i < 2 {
			if err != nil {
				t.Errorf("Failed to allocate port %d: %v", i, err)
			}
			tunnel.RemotePort = port
			ts.tunnels[tunnel.ID] = tunnel
		} else {
			if err == nil {
				t.Error("Expected port allocation to fail, but it succeeded")
			}
		}
	}
}

func TestRemoveTunnel(t *testing.T) {
	// Create a TunnelServer with a test tunnel
	ts := &TunnelServer{
		logger:      zap.NewExample(),
		tunnels:     make(map[string]*Tunnel),
		portManager: NewPortManager(10000, 10001),
	}

	// Create a test tunnel
	tunnel := &Tunnel{
		ID:         "test1",
		Subdomain:  "test1.example.com",
		LocalPort:  8080,
		RemotePort: 10000,
		CreatedAt:  time.Now(),
		LastActive: time.Now(),
	}

	// Add the tunnel and mark the port as used
	ts.mu.Lock()
	ts.tunnels[tunnel.ID] = tunnel
	ts.portManager.usedPorts[10000] = true
	ts.mu.Unlock()

	// Verify initial state
	if ts.portManager.IsPortAvailable(10000) {
		t.Error("Port 10000 should be marked as used initially")
	}

	// Remove the tunnel
	ts.removeTunnel(tunnel.ID)

	// Verify tunnel was removed
	ts.mu.RLock()
	_, exists := ts.tunnels[tunnel.ID]
	ts.mu.RUnlock()

	if exists {
		t.Error("Tunnel was not removed from the tunnels map")
	}

	// Verify port was released
	if !ts.portManager.IsPortAvailable(10000) {
		t.Error("Port 10000 was not released after tunnel removal")
	}

	// Try to remove a non-existent tunnel (should not panic)
	ts.removeTunnel("non-existent-id")
}

func TestServeHTTP(t *testing.T) {
	ts := &TunnelServer{
		logger:         zap.NewExample(),
		tunnels:        make(map[string]*Tunnel),
		portManager:    NewPortManager(10000, 20000),
		AllowedDomains: []string{"example.com"},
		Timeout:        5 * time.Second,
	}

	// Create a test tunnel
	tunnel := &Tunnel{
		ID:         "test1",
		Subdomain:  "test.example.com",
		LocalPort:  8080,
		RemotePort: 10000,
		TargetHost: "localhost",
		CreatedAt:  time.Now(),
		LastActive: time.Now(),
	}

	ts.mu.Lock()
	ts.tunnels[tunnel.ID] = tunnel
	ts.mu.Unlock()

	tests := []struct {
		name          string
		host          string
		expectedCode  int
		expectedError bool
	}{
		{
			name:          "matching tunnel",
			host:          "test.example.com",
			expectedCode:  http.StatusOK,
			expectedError: false,
		},
		{
			name:          "non-existing tunnel",
			host:          "nonexistent.example.com",
			expectedCode:  http.StatusOK, // Should pass to next handler
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://"+tt.host+"/test", nil)
			w := httptest.NewRecorder()

			err := ts.ServeHTTP(w, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
				return nil
			}))

			if (err != nil) != tt.expectedError {
				t.Errorf("ServeHTTP() error = %v, expectedError %v", err, tt.expectedError)
			}
		})
	}
}

func TestUnmarshalCaddyfile(t *testing.T) {
	tests := []struct {
		name           string
		config         string
		expectedError  bool
		validateConfig func(*testing.T, *TunnelServer)
	}{
		{
			name: "valid configuration",
			config: `fops_tunnel {
				ssh_port 2222
				auth_keys_path /path/to/keys
				allowed_domains example.com test.com
				timeout 1h
			}`,
			expectedError: false,
			validateConfig: func(t *testing.T, ts *TunnelServer) {
				if ts.SSHPort != 2222 {
					t.Errorf("Expected SSHPort 2222, got %d", ts.SSHPort)
				}
				if ts.AuthKeysPath != "/path/to/keys" {
					t.Errorf("Expected AuthKeysPath /path/to/keys, got %s", ts.AuthKeysPath)
				}
				if len(ts.AllowedDomains) != 2 {
					t.Errorf("Expected 2 allowed domains, got %d", len(ts.AllowedDomains))
				}
				if ts.Timeout != time.Hour {
					t.Errorf("Expected timeout 1h, got %v", ts.Timeout)
				}
			},
		},
		{
			name: "missing auth_keys_path",
			config: `fops_tunnel {
				ssh_port 2222
				allowed_domains example.com
			}`,
			expectedError: true,
		},
		{
			name: "missing allowed_domains",
			config: `fops_tunnel {
				ssh_port 2222
				auth_keys_path /path/to/keys
			}`,
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := &TunnelServer{}
			d := caddyfile.NewTestDispenser(tt.config)

			err := ts.UnmarshalCaddyfile(d)

			if (err != nil) != tt.expectedError {
				t.Errorf("UnmarshalCaddyfile() error = %v, expectedError %v", err, tt.expectedError)
			}

			if err == nil && tt.validateConfig != nil {
				tt.validateConfig(t, ts)
			}
		})
	}
}

func TestUpdateTunnelActivity(t *testing.T) {
	ts := &TunnelServer{
		logger:  zap.NewExample(),
		tunnels: make(map[string]*Tunnel),
	}

	// Create a test tunnel
	tunnel := &Tunnel{
		ID:         "test1",
		LastActive: time.Now().Add(-time.Hour), // Old activity
	}

	ts.mu.Lock()
	ts.tunnels[tunnel.ID] = tunnel
	ts.mu.Unlock()

	tests := []struct {
		name     string
		tunnelID string
		want     bool
	}{
		{
			name:     "existing tunnel",
			tunnelID: "test1",
			want:     true,
		},
		{
			name:     "non-existing tunnel",
			tunnelID: "nonexistent",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oldActivity := tunnel.LastActive
			got := ts.UpdateTunnelActivity(tt.tunnelID)

			if got != tt.want {
				t.Errorf("UpdateTunnelActivity() = %v, want %v", got, tt.want)
			}

			if tt.want && tunnel.LastActive.Equal(oldActivity) {
				t.Error("LastActive time was not updated")
			}
		})
	}
}
