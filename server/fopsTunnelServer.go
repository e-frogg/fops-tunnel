package server

import (
	_ "embed"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/gorilla/mux"
	"go.uber.org/zap"
)

//go:embed static/no_tunnel.html
var noTunnelHTML []byte

// TunnelServer represents the main tunnel server configuration
type TunnelServer struct {
	logger *zap.Logger

	// Configuration
	SSHPort        int           `json:"ssh_port,omitempty"`
	AdminToken     string        `json:"admin_api_token,omitempty"`
	AllowedDomains []string      `json:"allowed_domains,omitempty"`
	AuthKeysPath   string        `json:"auth_keys_path,omitempty"`
	Timeout        time.Duration `json:"timeout,omitempty"`

	// Runtime state
	tunnels     map[string]*Tunnel
	portManager *PortManager
	mu          sync.RWMutex
	stopCleanup chan struct{}
	sshServer   *SSHServer
}

// Tunnel represents an active tunnel connection
type Tunnel struct {
	ID             string
	Subdomain      string
	LocalPort      int    // Port on the target that we're forwarding to
	RemotePort     int    // Port allocated on the server side
	TargetHost     string // Host to forward to (can be localhost or any reachable host)
	CreatedAt      time.Time
	LastActive     time.Time
	listener       net.Listener
	stopForwarding chan struct{}
	mu             sync.Mutex // Protects LastActive field
}

func init() {
	caddy.RegisterModule(&TunnelServer{})
	httpcaddyfile.RegisterHandlerDirective("fops_tunnel", parseCaddyfile)
}

// Interface guards
var (
	_ caddy.Module                = (*TunnelServer)(nil)
	_ caddy.Provisioner           = (*TunnelServer)(nil)
	_ caddy.CleanerUpper          = (*TunnelServer)(nil)
	_ caddyhttp.MiddlewareHandler = (*TunnelServer)(nil)
	_ caddyfile.Unmarshaler       = (*TunnelServer)(nil)
)

// parseCaddyfile parses the fops_tunnel directive. It's called by Caddy when loading the configuration.
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var ts TunnelServer
	err := ts.UnmarshalCaddyfile(h.Dispenser)
	return &ts, err
}

// CaddyModule returns the Caddy module information.
func (*TunnelServer) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "http.handlers.fops_tunnel",
		New: func() caddy.Module {
			return &TunnelServer{
				tunnels:     make(map[string]*Tunnel),
				stopCleanup: make(chan struct{}),
			}
		},
	}
}

// Provision implements caddy.Provisioner.
func (ts *TunnelServer) Provision(ctx caddy.Context) error {
	ts.logger = ctx.Logger()
	ts.tunnels = make(map[string]*Tunnel)
	ts.portManager = NewPortManager(10000, 20000)
	ts.stopCleanup = make(chan struct{})

	// Start SSH server
	var err error
	ts.sshServer, err = NewSSHServer(ts)
	if err != nil {
		return fmt.Errorf("failed to create SSH server: %v", err)
	}

	// Start cleanup goroutine
	go ts.cleanupRoutine()

	return ts.sshServer.Start()
}

// Cleanup implements caddy.CleanerUpper.
func (ts *TunnelServer) Cleanup() error {
	if ts.sshServer != nil {
		return ts.sshServer.Close()
	}
	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (ts *TunnelServer) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// Check if this is an admin API request
	if strings.HasPrefix(r.URL.Path, "/fops-tunnel-api/") {
		// Verify admin token
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header required", http.StatusUnauthorized)
			return nil
		}

		// Expected format: "Bearer <token>"
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			http.Error(w, "Invalid authorization format", http.StatusUnauthorized)
			return nil
		}

		if parts[1] != ts.AdminToken {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return nil
		}

		adminHandler := NewAdminHandler(ts)
		router := mux.NewRouter()
		adminHandler.RegisterRoutes(router)
		router.ServeHTTP(w, r)
		return nil
	}

	// Handle regular tunnel requests
	host, _, _ := net.SplitHostPort(r.Host)
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	ts.logger.Debug("received request",
		zap.String("host", host),
		zap.String("method", r.Method),
		zap.String("path", r.URL.Path))

	// Find tunnel by subdomain
	for _, tunnel := range ts.tunnels {
		ts.logger.Debug("comparing hosts",
			zap.String("request_host", host),
			zap.String("tunnel_subdomain", tunnel.Subdomain))

		if tunnel.Subdomain == host {
			// Update tunnel activity
			tunnel.mu.Lock()
			tunnel.LastActive = time.Now()
			tunnel.mu.Unlock()

			ts.logger.Debug("found matching tunnel",
				zap.String("tunnel_id", tunnel.ID),
				zap.Int("local_port", tunnel.LocalPort))

			// Forward the request
			proxy := &httputil.ReverseProxy{
				Director: func(req *http.Request) {
					req.URL.Scheme = "http"
					req.URL.Host = fmt.Sprintf("%s:%d", tunnel.TargetHost, tunnel.LocalPort)
					req.Host = r.Host
					ts.logger.Debug("proxying request",
						zap.String("scheme", req.URL.Scheme),
						zap.String("host", req.URL.Host),
						zap.String("path", req.URL.Path))
				},
				ErrorHandler: func(rw http.ResponseWriter, req *http.Request, err error) {
					ts.logger.Error("proxy error",
						zap.Error(err),
						zap.String("tunnel_id", tunnel.ID))
					http.Error(rw, err.Error(), http.StatusBadGateway)
				},
				ModifyResponse: func(resp *http.Response) error {
					ts.logger.Debug("received response",
						zap.Int("status", resp.StatusCode),
						zap.Int64("content_length", resp.ContentLength))
					return nil
				},
			}

			proxy.ServeHTTP(w, r)
			return nil
		}
	}

	ts.logger.Debug("no matching tunnel found, serving static page",
		zap.Int("num_tunnels", len(ts.tunnels)))

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusTeapot)

	// Serve the embedded HTML file
	if _, err := w.Write(noTunnelHTML); err != nil {
		ts.logger.Error("Failed to write response", zap.Error(err))
		return fmt.Errorf("failed to write response: %v", err)
	}
	return nil
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (ts *TunnelServer) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	ts.tunnels = make(map[string]*Tunnel)
	ts.stopCleanup = make(chan struct{})

	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "admin_api_token":
				if !d.NextArg() {
					return d.ArgErr()
				}
				ts.AdminToken = d.Val()
			case "ssh_port":
				if !d.NextArg() {
					return d.ArgErr()
				}
				port, err := strconv.Atoi(d.Val())
				if err != nil {
					return fmt.Errorf("invalid ssh_port: %v", err)
				}
				ts.SSHPort = port

			case "auth_keys_path":
				if !d.NextArg() {
					return d.ArgErr()
				}
				ts.AuthKeysPath = d.Val()

			case "allowed_domains":
				ts.AllowedDomains = []string{}
				for d.NextArg() {
					ts.AllowedDomains = append(ts.AllowedDomains, d.Val())
				}

			case "timeout":
				if !d.NextArg() {
					return d.ArgErr()
				}
				duration, err := time.ParseDuration(d.Val())
				if err != nil {
					return fmt.Errorf("invalid timeout duration: %v", err)
				}
				ts.Timeout = duration

			default:
				return d.Errf("unknown subdirective %s", d.Val())
			}
		}
	}

	// Validate configuration
	if ts.SSHPort == 0 {
		ts.SSHPort = 2222 // default SSH port
	}
	if ts.AuthKeysPath == "" {
		return fmt.Errorf("auth_keys_path is required")
	}
	if len(ts.AllowedDomains) == 0 {
		return fmt.Errorf("at least one allowed_domain is required")
	}
	if ts.Timeout == 0 {
		ts.Timeout = time.Hour // default timeout
	}

	return nil
}

// cleanupRoutine periodically checks for and removes expired tunnels
func (ts *TunnelServer) cleanupRoutine() {
	ticker := time.NewTicker(50 * time.Millisecond) // More frequent checks for testing
	defer ticker.Stop()

	for {
		select {
		case <-ts.stopCleanup:
			return
		case <-ticker.C:
			ts.mu.Lock()
			now := time.Now()
			for id, tunnel := range ts.tunnels {
				tunnel.mu.Lock()
				inactiveTime := now.Sub(tunnel.LastActive)
				tunnel.mu.Unlock()

				if inactiveTime > ts.Timeout {
					ts.logger.Info("removing expired tunnel",
						zap.String("id", id),
						zap.String("subdomain", tunnel.Subdomain),
						zap.Duration("inactive_time", inactiveTime))

					// Close the tunnel before removing it
					if err := tunnel.Close(); err != nil {
						ts.logger.Error("failed to close tunnel", zap.String("id", id), zap.Error(err))
					}
					ts.portManager.ReleasePort(tunnel.RemotePort)
					delete(ts.tunnels, id)
				}
			}
			ts.mu.Unlock()
		}
	}
}

// UpdateTunnelActivity updates the LastActive time for a tunnel
func (ts *TunnelServer) UpdateTunnelActivity(id string) bool {
	ts.mu.Lock()
	tunnel, exists := ts.tunnels[id]
	ts.mu.Unlock()

	if exists {
		tunnel.mu.Lock()
		tunnel.LastActive = time.Now()
		lastActive := tunnel.LastActive
		tunnel.mu.Unlock()

		ts.logger.Debug("updated tunnel activity",
			zap.String("id", id),
			zap.Time("last_active", lastActive))
		return true
	}
	return false
}

// removeTunnel safely removes a tunnel and frees its resources
func (ts *TunnelServer) removeTunnel(id string) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	if tunnel, exists := ts.tunnels[id]; exists {
		if err := tunnel.Close(); err != nil {
			ts.logger.Error("failed to close tunnel", zap.String("id", id), zap.Error(err))
		}
		ts.portManager.ReleasePort(tunnel.RemotePort)
		delete(ts.tunnels, id)
		ts.logger.Info("tunnel removed", zap.String("id", id))
	}
}

// Close closes the tunnel and releases its resources
func (t *Tunnel) Close() error {
	if t.stopForwarding != nil {
		close(t.stopForwarding)
	}
	if t.listener != nil {
		return t.listener.Close()
	}
	return nil
}
