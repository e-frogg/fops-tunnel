package server

import (
	"sort"
	"testing"
)

// Helper function to create a PortManager with default test range
func newTestPortManager(t *testing.T) *PortManager {
	return NewPortManager(10000, 10002)
}

// Helper function to allocate n ports and return them
func allocatePorts(t *testing.T, pm *PortManager, n int) []int {
	ports := make([]int, n)
	for i := 0; i < n; i++ {
		port, err := pm.AllocatePort()
		if err != nil {
			t.Fatalf("Failed to allocate port %d: %v", i+1, err)
		}
		ports[i] = port
	}
	return ports
}

func TestPortManagerAllocation(t *testing.T) {
	tests := []struct {
		name          string
		allocateCount int
		wantErr       bool
		expectedPorts []int
	}{
		{
			name:          "allocate single port",
			allocateCount: 1,
			wantErr:       false,
			expectedPorts: []int{10000},
		},
		{
			name:          "allocate all available ports",
			allocateCount: 3,
			wantErr:       false,
			expectedPorts: []int{10000, 10001, 10002},
		},
		{
			name:          "attempt to over-allocate",
			allocateCount: 4,
			wantErr:       true,
			expectedPorts: []int{10000, 10001, 10002},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pm := newTestPortManager(t)
			var allocatedPorts []int

			// Allocate ports
			for i := 0; i < tt.allocateCount; i++ {
				port, err := pm.AllocatePort()
				if err != nil {
					if !tt.wantErr {
						t.Fatalf("unexpected error: %v", err)
					}
					return
				}
				allocatedPorts = append(allocatedPorts, port)
			}

			// Verify allocated ports
			if !tt.wantErr {
				if len(allocatedPorts) != len(tt.expectedPorts) {
					t.Errorf("got %d ports, want %d ports", len(allocatedPorts), len(tt.expectedPorts))
				}
				for i, want := range tt.expectedPorts {
					if allocatedPorts[i] != want {
						t.Errorf("port[%d] = %d, want %d", i, allocatedPorts[i], want)
					}
				}
			}
		})
	}
}

func TestPortManagerReleaseAndReallocation(t *testing.T) {
	pm := newTestPortManager(t)

	// Initial allocation
	ports := allocatePorts(t, pm, 3)

	// Release middle port
	middlePort := ports[1]
	pm.ReleasePort(middlePort)

	// Verify middle port is available
	if !pm.IsPortAvailable(middlePort) {
		t.Errorf("Port %d should be available after release", middlePort)
	}

	// Reallocate port
	newPort, err := pm.AllocatePort()
	if err != nil {
		t.Fatalf("Failed to reallocate port: %v", err)
	}
	if newPort != middlePort {
		t.Errorf("Expected to get released port %d, got %d", middlePort, newPort)
	}
}

func TestPortManagerConcurrency(t *testing.T) {
	pm := NewPortManager(10000, 10010)
	const numWorkers = 5
	const portsPerWorker = 2

	// Channel to collect allocated ports
	ports := make(chan int, numWorkers*portsPerWorker)
	done := make(chan bool)

	// Start workers to allocate ports
	for i := 0; i < numWorkers; i++ {
		go func() {
			for j := 0; j < portsPerWorker; j++ {
				port, err := pm.AllocatePort()
				if err != nil {
					t.Errorf("Failed to allocate port: %v", err)
					return
				}
				ports <- port
			}
			done <- true
		}()
	}

	// Wait for all workers to finish
	for i := 0; i < numWorkers; i++ {
		<-done
	}
	close(ports)

	// Collect all allocated ports
	allocatedPorts := make([]int, 0, numWorkers*portsPerWorker)
	for port := range ports {
		allocatedPorts = append(allocatedPorts, port)
	}

	// Verify all ports are unique and within range
	sort.Ints(allocatedPorts)
	for i, port := range allocatedPorts {
		if i > 0 && port == allocatedPorts[i-1] {
			t.Errorf("Duplicate port allocated: %d", port)
		}
		if port < 10000 || port > 10010 {
			t.Errorf("Port %d outside valid range", port)
		}
	}

	// Verify the number of allocated ports
	if len(allocatedPorts) != numWorkers*portsPerWorker {
		t.Errorf("Expected %d ports, got %d", numWorkers*portsPerWorker, len(allocatedPorts))
	}
}

func TestPortManagerRangeValidation(t *testing.T) {
	pm := NewPortManager(10000, 10002)

	// Test out of range ports
	if pm.IsPortAvailable(9999) {
		t.Error("Port below range should not be available")
	}
	if pm.IsPortAvailable(10003) {
		t.Error("Port above range should not be available")
	}

	// Test releasing out of range ports
	pm.ReleasePort(9999)  // Should not panic
	pm.ReleasePort(10003) // Should not panic

	// Verify range is still valid
	port, err := pm.AllocatePort()
	if err != nil {
		t.Fatalf("Failed to allocate port after out-of-range operations: %v", err)
	}
	if port != 10000 {
		t.Errorf("Expected first port to be 10000, got %d", port)
	}
}

func TestPortManagerGetUsedPorts(t *testing.T) {
	pm := NewPortManager(10000, 10002)

	// Initially no ports should be used
	if ports := pm.GetUsedPorts(); len(ports) != 0 {
		t.Errorf("Expected no used ports initially, got %v", ports)
	}

	// Allocate some ports
	port1, _ := pm.AllocatePort()
	port2, _ := pm.AllocatePort()

	// Check used ports
	usedPorts := pm.GetUsedPorts()
	if len(usedPorts) != 2 {
		t.Errorf("Expected 2 used ports, got %d", len(usedPorts))
	}

	// Verify the correct ports are reported as used
	sort.Ints(usedPorts)
	if usedPorts[0] != port1 || usedPorts[1] != port2 {
		t.Errorf("Expected ports %d and %d, got %v", port1, port2, usedPorts)
	}

	// Release a port and verify it's no longer reported
	pm.ReleasePort(port1)
	usedPorts = pm.GetUsedPorts()
	if len(usedPorts) != 1 || usedPorts[0] != port2 {
		t.Errorf("Expected only port %d to be used, got %v", port2, usedPorts)
	}
}

func TestPortManagerEdgeCases(t *testing.T) {
	tests := []struct {
		name string
		test func(*testing.T)
	}{
		{
			name: "release non-existent port",
			test: func(t *testing.T) {
				pm := newTestPortManager(t)
				pm.ReleasePort(9999) // Should not panic
			},
		},
		{
			name: "release already released port",
			test: func(t *testing.T) {
				pm := newTestPortManager(t)
				port, _ := pm.AllocatePort()
				pm.ReleasePort(port)
				pm.ReleasePort(port) // Should not panic or cause issues
			},
		},
		{
			name: "allocate after releasing all ports",
			test: func(t *testing.T) {
				pm := newTestPortManager(t)
				ports := allocatePorts(t, pm, 3)
				for _, port := range ports {
					pm.ReleasePort(port)
				}
				newPort, err := pm.AllocatePort()
				if err != nil {
					t.Errorf("Failed to allocate after releasing all ports: %v", err)
				}
				if newPort != 10000 {
					t.Errorf("Expected first available port, got %d", newPort)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, tt.test)
	}
}
