package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestHandleListTunnels(t *testing.T) {
	// Create a TunnelServer with some test tunnels
	ts := &TunnelServer{
		logger:      zap.NewExample(),
		tunnels:     make(map[string]*Tunnel),
		portManager: NewPortManager(10000, 20000),
	}

	// Add some test tunnels
	now := time.Now()
	testTunnels := []*Tunnel{
		{
			ID:         "test1",
			Subdomain:  "test1.example.com",
			LocalPort:  8080,
			RemotePort: 10000,
			CreatedAt:  now,
		},
		{
			ID:         "test2",
			Subdomain:  "test2.example.com",
			LocalPort:  8081,
			RemotePort: 10001,
			CreatedAt:  now,
		},
	}

	for _, tunnel := range testTunnels {
		ts.tunnels[tunnel.ID] = tunnel
	}

	// Create an AdminHandler with our test TunnelServer
	ah := &AdminHandler{server: ts}

	// Create a test request
	req := httptest.NewRequest("GET", "/api/tunnels", nil)
	w := httptest.NewRecorder()

	// Call the handler
	ah.handleListTunnels(w, req)

	// Check response status code
	if w.Code != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, w.Code)
	}

	// Check Content-Type header
	contentType := w.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Expected Content-Type %s, got %s", "application/json", contentType)
	}

	// Parse response body
	var tunnels []TunnelInfo
	if err := json.NewDecoder(w.Body).Decode(&tunnels); err != nil {
		t.Fatalf("Failed to decode response body: %v", err)
	}

	// Verify number of tunnels
	if len(tunnels) != len(testTunnels) {
		t.Errorf("Expected %d tunnels, got %d", len(testTunnels), len(tunnels))
	}

	// Create a map of expected tunnels for easy lookup
	expectedTunnels := make(map[string]TunnelInfo)
	for _, tt := range testTunnels {
		expectedTunnels[tt.ID] = TunnelInfo{
			ID:         tt.ID,
			Subdomain:  tt.Subdomain,
			LocalPort:  tt.LocalPort,
			RemotePort: tt.RemotePort,
			CreatedAt:  tt.CreatedAt,
		}
	}

	// Verify each tunnel in the response
	for _, tunnel := range tunnels {
		expected, exists := expectedTunnels[tunnel.ID]
		if !exists {
			t.Errorf("Unexpected tunnel ID in response: %s", tunnel.ID)
			continue
		}

		if tunnel.Subdomain != expected.Subdomain {
			t.Errorf("Expected subdomain %s, got %s", expected.Subdomain, tunnel.Subdomain)
		}
		if tunnel.LocalPort != expected.LocalPort {
			t.Errorf("Expected local port %d, got %d", expected.LocalPort, tunnel.LocalPort)
		}
		if tunnel.RemotePort != expected.RemotePort {
			t.Errorf("Expected remote port %d, got %d", expected.RemotePort, tunnel.RemotePort)
		}
		if !tunnel.CreatedAt.Equal(expected.CreatedAt) {
			t.Errorf("Expected created at %v, got %v", expected.CreatedAt, tunnel.CreatedAt)
		}
	}
}
