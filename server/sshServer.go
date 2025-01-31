package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"io/ioutil"
	mathrand "math/rand"
	"net"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

// TunnelRequest represents the data sent when requesting a new tunnel
type TunnelRequest struct {
	TargetPort    uint32
	TargetHost    string
	SubdomainSeed string
}

// SSHServer handles SSH connections and tunnel requests
type SSHServer struct {
	config     *ssh.ServerConfig
	tunnelServ *TunnelServer
	listener   net.Listener
	mu         sync.Mutex
	wg         sync.WaitGroup
	done       chan struct{}
}

// NewSSHServer creates a new SSH server instance
func NewSSHServer(ts *TunnelServer) (*SSHServer, error) {
	server := &SSHServer{
		tunnelServ: ts,
		config:     &ssh.ServerConfig{},
		done:       make(chan struct{}),
	}

	// Generate server key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate server key: %v", err)
	}

	hostKey, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create host key signer: %v", err)
	}

	server.config.AddHostKey(hostKey)

	// Read authorized keys
	authorizedKeysBytes, err := ioutil.ReadFile(ts.AuthKeysPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read authorized_keys file: %v", err)
	}

	ts.logger.Debug("authorized keys content", zap.String("content", string(authorizedKeysBytes)))

	authorizedKeys := make(map[string]bool)
	for _, line := range strings.Split(string(authorizedKeysBytes), "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
			ts.logger.Debug("processing authorized key line",
				zap.String("raw_line", line),
				zap.Int("raw_length", len(line)))

			// Parse the public key to normalize it
			pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
			if err != nil {
				ts.logger.Error("failed to parse authorized key",
					zap.String("line", line),
					zap.Error(err))
				continue
			}

			// Store the normalized form
			normalizedKey := string(ssh.MarshalAuthorizedKey(pubKey))
			normalizedKey = strings.TrimSpace(normalizedKey)
			authorizedKeys[normalizedKey] = true

			ts.logger.Debug("added normalized authorized key",
				zap.String("normalized_key", normalizedKey),
				zap.Int("normalized_length", len(normalizedKey)))
		}
	}

	server.config.PublicKeyCallback = func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		// Marshal the incoming key in OpenSSH authorized_keys format
		authKey := string(ssh.MarshalAuthorizedKey(key))
		authKey = strings.TrimSpace(authKey)

		ts.logger.Debug("checking incoming key",
			zap.String("user", conn.User()),
			zap.String("key_type", key.Type()),
			zap.String("raw_auth_key", authKey),
			zap.Int("key_length", len(authKey)))

		ts.logger.Debug("comparing with authorized keys")
		for storedKey := range authorizedKeys {
			ts.logger.Debug("comparing with stored key",
				zap.String("stored_key", storedKey),
				zap.Int("stored_length", len(storedKey)),
				zap.Bool("matches", storedKey == authKey))
		}

		if authorizedKeys[authKey] {
			ts.logger.Debug("key authorized successfully")
			return &ssh.Permissions{
				Extensions: map[string]string{
					"pubkey": authKey,
				},
			}, nil
		}
		ts.logger.Debug("key not authorized - no match found in authorized keys")
		return nil, fmt.Errorf("unknown public key")
	}

	return server, nil
}

// Start starts the SSH server
func (s *SSHServer) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.listener != nil {
		return fmt.Errorf("server already started")
	}

	// Start listening
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", s.tunnelServ.SSHPort))
	if err != nil {
		return fmt.Errorf("failed to listen on port %d: %v", s.tunnelServ.SSHPort, err)
	}
	s.listener = listener

	// Accept connections
	s.wg.Add(1)
	go s.acceptConnections()

	return nil
}

// Close stops the SSH server and cleans up resources
func (s *SSHServer) Close() error {
	s.tunnelServ.logger.Info("Starting server shutdown")

	s.mu.Lock()
	if s.listener != nil {
		s.tunnelServ.logger.Debug("Closing listener")
		s.listener.Close()
		s.tunnelServ.logger.Debug("Signaling shutdown via done channel")
		close(s.done)
	}
	s.mu.Unlock()

	// Create a timeout channel
	timeout := time.After(5 * time.Second)

	// Wait for goroutines with timeout
	done := make(chan struct{})
	go func() {
		s.tunnelServ.logger.Debug("Waiting for all goroutines to complete")
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		s.tunnelServ.logger.Info("Server shutdown completed successfully")
	case <-timeout:
		s.tunnelServ.logger.Warn("Server shutdown timed out waiting for goroutines")
	}

	return nil
}

// acceptConnections handles incoming SSH connections
func (s *SSHServer) acceptConnections() {
	defer func() {
		s.tunnelServ.logger.Debug("Accept loop ending")
		s.wg.Done()
	}()

	for {
		select {
		case <-s.done:
			s.tunnelServ.logger.Debug("Accept loop received shutdown signal")
			return
		default:
			nConn, err := s.listener.Accept()
			if err != nil {
				if !strings.Contains(err.Error(), "use of closed network connection") {
					s.tunnelServ.logger.Error("failed to accept connection", zap.Error(err))
				} else {
					s.tunnelServ.logger.Debug("Listener closed")
				}
				return
			}

			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				s.handleConnection(nConn)
			}()
		}
	}
}

// handleConnection processes a single SSH connection
func (s *SSHServer) handleConnection(conn net.Conn) {
	remoteAddr := conn.RemoteAddr().String()
	s.tunnelServ.logger.Info("New connection received", zap.String("remote_addr", remoteAddr))

	// Create a context with timeout for the entire connection
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create done channel for this connection
	connDone := make(chan struct{})
	defer close(connDone)

	defer func() {
		s.tunnelServ.logger.Info("Connection closing", zap.String("remote_addr", remoteAddr))
		conn.Close()
	}()

	// Handle connection in a goroutine
	go func() {
		defer func() {
			if r := recover(); r != nil {
				s.tunnelServ.logger.Error("Panic in connection handler",
					zap.String("remote_addr", remoteAddr),
					zap.Any("panic", r))
			}
		}()

		// Perform SSH handshake
		s.tunnelServ.logger.Debug("Starting SSH handshake", zap.String("remote_addr", remoteAddr))
		sshConn, chans, reqs, err := ssh.NewServerConn(conn, s.config)
		if err != nil {
			s.tunnelServ.logger.Error("SSH handshake failed",
				zap.String("remote_addr", remoteAddr),
				zap.Error(err))
			return
		}

		s.tunnelServ.logger.Info("SSH handshake successful",
			zap.String("remote_addr", remoteAddr),
			zap.String("user", sshConn.User()))

		defer func() {
			s.tunnelServ.logger.Info("SSH connection closing",
				zap.String("remote_addr", remoteAddr),
				zap.String("user", sshConn.User()))
			sshConn.Close()
		}()

		// Start a goroutine to handle global requests
		go func() {
			s.tunnelServ.logger.Debug("Starting global request discarder",
				zap.String("remote_addr", remoteAddr))
			ssh.DiscardRequests(reqs)
			s.tunnelServ.logger.Debug("Global request discarder ended",
				zap.String("remote_addr", remoteAddr))
		}()

		// Handle channels
		s.tunnelServ.logger.Debug("Starting channel handler loop",
			zap.String("remote_addr", remoteAddr))

		for {
			select {
			case newChannel, ok := <-chans:
				if !ok {
					s.tunnelServ.logger.Debug("Channel stream closed",
						zap.String("remote_addr", remoteAddr))
					return
				}

				s.tunnelServ.logger.Debug("New channel request",
					zap.String("remote_addr", remoteAddr),
					zap.String("type", newChannel.ChannelType()))

				if newChannel.ChannelType() != "tunnel" && newChannel.ChannelType() != "session" {
					s.tunnelServ.logger.Debug("Rejecting channel",
						zap.String("remote_addr", remoteAddr),
						zap.String("type", newChannel.ChannelType()))
					newChannel.Reject(ssh.UnknownChannelType, "only tunnel and session channels are supported")
					continue
				}

				channel, requests, err := newChannel.Accept()
				if err != nil {
					s.tunnelServ.logger.Error("Failed to accept channel",
						zap.String("remote_addr", remoteAddr),
						zap.Error(err))
					continue
				}

				s.tunnelServ.logger.Info("Channel accepted",
					zap.String("remote_addr", remoteAddr),
					zap.String("type", newChannel.ChannelType()))

				if newChannel.ChannelType() == "session" {
					go s.handleSession(channel, requests)
				} else {
					go s.handleChannel(channel, requests)
				}

			case <-ctx.Done():
				s.tunnelServ.logger.Info("Connection context cancelled",
					zap.String("remote_addr", remoteAddr))
				return

			case <-s.done:
				s.tunnelServ.logger.Info("Server shutdown signal received",
					zap.String("remote_addr", remoteAddr))
				return
			}
		}
	}()

	// Wait for either completion or shutdown
	select {
	case <-connDone:
		s.tunnelServ.logger.Debug("Connection handler completed normally",
			zap.String("remote_addr", remoteAddr))
	case <-ctx.Done():
		s.tunnelServ.logger.Warn("Connection handler timed out",
			zap.String("remote_addr", remoteAddr))
	case <-s.done:
		s.tunnelServ.logger.Info("Connection handler interrupted by server shutdown",
			zap.String("remote_addr", remoteAddr))
	}
}

// handleSession gère une session SSH interactive
func (s *SSHServer) handleSession(channel ssh.Channel, requests <-chan *ssh.Request) {
	s.tunnelServ.logger.Info("New SSH session started")
	defer func() {
		s.tunnelServ.logger.Info("SSH session ending")
		channel.Close()
	}()

	for req := range requests {
		s.tunnelServ.logger.Debug("Session request received",
			zap.String("type", req.Type),
			zap.Bool("want_reply", req.WantReply))

		ok := false
		switch req.Type {
		case "shell", "pty-req":
			s.tunnelServ.logger.Debug("Handling shell/pty request",
				zap.String("type", req.Type))
			ok = true
			if req.WantReply {
				s.tunnelServ.logger.Debug("Sending positive reply for shell/pty request")
				req.Reply(ok, nil)
			}
			if req.Type == "shell" {
				s.tunnelServ.logger.Info("Sending shell not supported message")
				io.WriteString(channel, "Interactive shell is not supported. This is a tunnel server.\n")
				s.tunnelServ.logger.Debug("Closing channel after shell message")
				channel.Close()
				return
			}
		default:
			s.tunnelServ.logger.Debug("Rejecting unknown request type",
				zap.String("type", req.Type))
			if req.WantReply {
				req.Reply(ok, nil)
			}
		}
	}
	s.tunnelServ.logger.Info("Request channel closed")
}

// handleChannel handles the SSH channel and incoming requests, managing tunnels and responding to specific request types.
func (s *SSHServer) handleChannel(channel ssh.Channel, requests <-chan *ssh.Request) {
	defer channel.Close()

	var tunnel *Tunnel // Declare tunnel variable at function scope

	for req := range requests {
		s.tunnelServ.logger.Info("received request",
			zap.String("type", req.Type),
			zap.Bool("want_reply", req.WantReply))

		switch req.Type {
		case "tunnel-request":
			s.tunnelServ.logger.Debug("decoding tunnel request payload")
			var tunnelReq TunnelRequest
			if err := ssh.Unmarshal(req.Payload, &tunnelReq); err != nil {
				s.tunnelServ.logger.Error("failed to unmarshal tunnel request", zap.Error(err))
				if req.WantReply {
					req.Reply(false, []byte(err.Error()))
				}
				continue
			}

			s.tunnelServ.logger.Info("tunnel request received",
				zap.Uint32("target_port", tunnelReq.TargetPort),
				zap.String("target_host", tunnelReq.TargetHost),
				zap.String("subdomain_seed", tunnelReq.SubdomainSeed))

			if tunnelReq.SubdomainSeed == "" {
				errMsg := "subdomain is required"
				s.tunnelServ.logger.Error(errMsg)
				if req.WantReply {
					req.Reply(false, []byte(errMsg))
				}
				continue
			}

			// Check if subdomain is already in use
			s.tunnelServ.mu.RLock()
			for _, t := range s.tunnelServ.tunnels {
				if t.Subdomain == tunnelReq.SubdomainSeed {
					s.tunnelServ.mu.RUnlock()
					errMsg := fmt.Sprintf("subdomain %s is already in use", tunnelReq.SubdomainSeed)
					s.tunnelServ.logger.Error(errMsg)
					if req.WantReply {
						req.Reply(false, []byte(errMsg))
					}
					continue
				}
			}
			s.tunnelServ.mu.RUnlock()

			// Use the provided subdomain and append the domain
			subdomain := fmt.Sprintf("%s.%s", tunnelReq.SubdomainSeed, s.tunnelServ.AllowedDomains[0])

			s.tunnelServ.logger.Debug("using provided subdomain",
				zap.String("subdomain", subdomain))

			// Allocate port
			remotePort, err := s.tunnelServ.portManager.AllocatePort()
			if err != nil {
				s.tunnelServ.logger.Error("failed to allocate port", zap.Error(err))
				if req.WantReply {
					req.Reply(false, []byte(err.Error()))
				}
				continue
			}

			s.tunnelServ.logger.Debug("allocated remote port", zap.Int("port", remotePort))

			// Create tunnel
			tunnel = &Tunnel{
				ID:         generateID(),
				Subdomain:  subdomain,
				LocalPort:  int(tunnelReq.TargetPort),
				RemotePort: remotePort,
				TargetHost: tunnelReq.TargetHost,
				CreatedAt:  time.Now(),
				LastActive: time.Now(),
			}

			s.tunnelServ.logger.Debug("created tunnel object",
				zap.String("id", tunnel.ID),
				zap.String("subdomain", tunnel.Subdomain),
				zap.Int("local_port", tunnel.LocalPort),
				zap.Int("remote_port", tunnel.RemotePort))

			// Add tunnel to map
			s.tunnelServ.mu.Lock()
			s.tunnelServ.tunnels[tunnel.ID] = tunnel
			s.tunnelServ.mu.Unlock()

			s.tunnelServ.logger.Info("tunnel created",
				zap.String("id", tunnel.ID),
				zap.String("subdomain", tunnel.Subdomain),
				zap.Int("remote_port", tunnel.RemotePort))

			// Start port forwarding
			listener, err := net.Listen("tcp", fmt.Sprintf(":%d", tunnel.RemotePort))
			if err != nil {
				s.tunnelServ.logger.Error("failed to listen on remote port",
					zap.Int("port", tunnel.RemotePort),
					zap.Error(err))
				if req.WantReply {
					req.Reply(false, []byte(err.Error()))
				}
				s.tunnelServ.portManager.ReleasePort(tunnel.RemotePort)
				continue
			}

			tunnel.listener = listener
			tunnel.stopForwarding = make(chan struct{})

			// Start forwarding goroutine
			go func() {
				defer listener.Close()
				for {
					select {
					case <-tunnel.stopForwarding:
						return
					default:
						remoteConn, err := listener.Accept()
						if err != nil {
							if !strings.Contains(err.Error(), "use of closed network connection") {
								s.tunnelServ.logger.Error("failed to accept connection",
									zap.String("tunnel_id", tunnel.ID),
									zap.Error(err))
							}
							continue
						}

						go s.handleTunnelConnection(tunnel, remoteConn, channel)
					}
				}
			}()

			if req.WantReply {
				req.Reply(true, nil)
			}

		case "ping":
			// Handle ping request
			s.tunnelServ.logger.Debug("received ping request")

			if tunnel == nil {
				s.tunnelServ.logger.Error("received ping for non-existent tunnel")
				if req.WantReply {
					req.Reply(false, []byte("tunnel not established"))
				}
				continue
			}

			// Check if target port is still accessible
			targetAddr := fmt.Sprintf("%s:%d", tunnel.TargetHost, tunnel.LocalPort)
			conn, err := net.DialTimeout("tcp", targetAddr, 2*time.Second)
			if err != nil {
				s.tunnelServ.logger.Error("target port is not accessible",
					zap.String("tunnel_id", tunnel.ID),
					zap.String("target_addr", targetAddr),
					zap.Error(err))
				if req.WantReply {
					req.Reply(false, []byte(fmt.Sprintf("target port not accessible: %v", err)))
				}
				continue
			}
			conn.Close()

			// Update tunnel activity
			tunnel.LastActive = time.Now()

			if req.WantReply {
				req.Reply(true, nil)
			}

		default:
			s.tunnelServ.logger.Warn("unknown request type", zap.String("type", req.Type))
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}
}

// handleTunnelConnection forwards traffic between remote and local ports
func (s *SSHServer) handleTunnelConnection(tunnel *Tunnel, remoteConn net.Conn, channel ssh.Channel) {
	defer remoteConn.Close()

	// Update tunnel activity
	tunnel.LastActive = time.Now()

	// Forward to target host and port instead of always using localhost
	targetAddr := fmt.Sprintf("%s:%d", tunnel.TargetHost, tunnel.LocalPort)
	s.tunnelServ.logger.Debug("connecting to target",
		zap.String("target_addr", targetAddr))

	// Connect to the target host:port
	localConn, err := net.Dial("tcp", targetAddr)
	if err != nil {
		s.tunnelServ.logger.Error("failed to connect to target",
			zap.String("tunnel_id", tunnel.ID),
			zap.String("target_host", tunnel.TargetHost),
			zap.Int("target_port", tunnel.LocalPort),
			zap.Error(err))
		return
	}
	defer localConn.Close()

	// Start bidirectional copy
	errCh := make(chan error, 2)
	go func() {
		_, err := io.Copy(localConn, remoteConn)
		errCh <- err
	}()
	go func() {
		_, err := io.Copy(remoteConn, localConn)
		errCh <- err
	}()

	// Wait for either direction to finish
	err = <-errCh
	if err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
		s.tunnelServ.logger.Error("tunnel connection error",
			zap.String("tunnel_id", tunnel.ID),
			zap.Error(err))
	}
}

// generateID creates a unique identifier for tunnels
func generateID() string {
	b := make([]byte, 16)
	mathrand.Read(b)
	return fmt.Sprintf("%x", b)
}
