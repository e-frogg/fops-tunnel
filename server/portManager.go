package server

import (
	"fmt"
	"sync"
)

// PortManager handles port allocation and deallocation
type PortManager struct {
	mu        sync.Mutex
	startPort int
	endPort   int
	usedPorts map[int]bool
	nextPort  int // Track the next port to try
}

// NewPortManager creates a new port manager with the given port range
func NewPortManager(startPort, endPort int) *PortManager {
	return &PortManager{
		startPort: startPort,
		endPort:   endPort,
		usedPorts: make(map[int]bool),
		nextPort:  startPort,
	}
}

// AllocatePort finds and reserves the next available port
func (pm *PortManager) AllocatePort() (int, error) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	// Try from nextPort to endPort
	for port := pm.nextPort; port <= pm.endPort; port++ {
		if !pm.usedPorts[port] {
			pm.usedPorts[port] = true
			pm.nextPort = port + 1
			if pm.nextPort > pm.endPort {
				pm.nextPort = pm.startPort
			}
			return port, nil
		}
	}

	// If not found, try from startPort to nextPort-1
	for port := pm.startPort; port < pm.nextPort; port++ {
		if !pm.usedPorts[port] {
			pm.usedPorts[port] = true
			pm.nextPort = port + 1
			if pm.nextPort > pm.endPort {
				pm.nextPort = pm.startPort
			}
			return port, nil
		}
	}

	return 0, fmt.Errorf("no available ports in range %d-%d", pm.startPort, pm.endPort)
}

// ReleasePort releases a previously allocated port
func (pm *PortManager) ReleasePort(port int) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if port >= pm.startPort && port <= pm.endPort {
		delete(pm.usedPorts, port)
		// If the released port is before nextPort, update nextPort
		if port < pm.nextPort {
			pm.nextPort = port
		}
	}
}

// IsPortAvailable checks if a specific port is available
func (pm *PortManager) IsPortAvailable(port int) bool {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if port < pm.startPort || port > pm.endPort {
		return false
	}
	return !pm.usedPorts[port]
}

// GetUsedPorts returns a list of currently used ports
func (pm *PortManager) GetUsedPorts() []int {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	ports := make([]int, 0, len(pm.usedPorts))
	for port := range pm.usedPorts {
		ports = append(ports, port)
	}
	return ports
}

// UsedPortsCount returns the number of currently used ports
func (pm *PortManager) UsedPortsCount() int {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	return len(pm.usedPorts)
}
