package server

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"go.uber.org/zap"
)

// AdminHandler handles administrative API endpoints
type AdminHandler struct {
	server *TunnelServer
}

// NewAdminHandler creates a new AdminHandler
func NewAdminHandler(server *TunnelServer) *AdminHandler {
	return &AdminHandler{server: server}
}

// RegisterRoutes registers all admin routes
func (ah *AdminHandler) RegisterRoutes(router *mux.Router) {
	router.HandleFunc("/fops-tunnel-api/tunnels", ah.handleListTunnels).Methods("GET")
	router.HandleFunc("/fops-tunnel-api/tunnels/{id}", ah.handleGetTunnel).Methods("GET")
	router.HandleFunc("/fops-tunnel-api/tunnels/{id}", ah.handleDeleteTunnel).Methods("DELETE")
	router.HandleFunc("/fops-tunnel-api/metrics", ah.handleMetrics).Methods("GET")
}

// handleListTunnels returns the list of active tunnels
func (ah *AdminHandler) handleListTunnels(w http.ResponseWriter, r *http.Request) {
	ah.server.mu.RLock()
	tunnels := make([]TunnelInfo, 0, len(ah.server.tunnels))
	for _, t := range ah.server.tunnels {
		tunnels = append(tunnels, TunnelInfo{
			ID:         t.ID,
			Subdomain:  t.Subdomain,
			LocalPort:  t.LocalPort,
			RemotePort: t.RemotePort,
			CreatedAt:  t.CreatedAt,
			Status:     "active",
		})
	}
	ah.server.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(tunnels); err != nil {
		ah.server.logger.Error("Failed to encode tunnels", zap.Error(err))
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

// handleGetTunnel returns details about a specific tunnel
func (ah *AdminHandler) handleGetTunnel(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	ah.server.mu.RLock()
	tunnel, exists := ah.server.tunnels[id]
	ah.server.mu.RUnlock()

	if !exists {
		http.Error(w, "Tunnel not found", http.StatusNotFound)
		return
	}

	info := TunnelInfo{
		ID:         tunnel.ID,
		Subdomain:  tunnel.Subdomain,
		LocalPort:  tunnel.LocalPort,
		RemotePort: tunnel.RemotePort,
		CreatedAt:  tunnel.CreatedAt,
		Status:     "active",
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(info); err != nil {
		ah.server.logger.Error("Failed to encode info", zap.Error(err))
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

// handleDeleteTunnel forcefully closes a tunnel
func (ah *AdminHandler) handleDeleteTunnel(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	ah.server.mu.Lock()
	tunnel, exists := ah.server.tunnels[id]
	if exists {
		delete(ah.server.tunnels, id)
		ah.server.portManager.ReleasePort(tunnel.RemotePort)
	}
	ah.server.mu.Unlock()

	if !exists {
		http.Error(w, "Tunnel not found", http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleMetrics returns global metrics about tunnels
func (ah *AdminHandler) handleMetrics(w http.ResponseWriter, r *http.Request) {
	ah.server.mu.RLock()
	metrics := TunnelMetrics{
		ActiveTunnels: len(ah.server.tunnels),
		UsedPorts:     ah.server.portManager.UsedPortsCount(),
	}
	ah.server.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(metrics); err != nil {
		ah.server.logger.Error("Failed to encode metrics", zap.Error(err))
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

type TunnelInfo struct {
	ID         string    `json:"id"`
	Subdomain  string    `json:"subdomain"`
	LocalPort  int       `json:"local_port"`
	RemotePort int       `json:"remote_port"`
	CreatedAt  time.Time `json:"created_at"`
	Status     string    `json:"status"`
}

type TunnelMetrics struct {
	ActiveTunnels int `json:"active_tunnels"`
	UsedPorts     int `json:"used_ports"`
}
