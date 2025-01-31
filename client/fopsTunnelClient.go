package fopstunnel

import (
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// TunnelClient represents a client connection to the tunnel server
type TunnelClient struct {
	// SSH connection details
	Host           string
	Port           int
	User           string
	PrivateKeyPath string

	// Tunnel configuration
	TargetHost    string // Host to forward to (can be localhost or any reachable host)
	TargetPort    int    // Port on the target host
	SubdomainSeed string

	// Internal state
	sshClient  *ssh.Client
	sshChannel ssh.Channel
	logger     *log.Logger
	stopPing   chan struct{} // Channel to stop the ping routine
}

// NewTunnelClient creates a new tunnel client instance
func NewTunnelClient(host string, port int, user string, privateKeyPath string) *TunnelClient {
	return &TunnelClient{
		Host:           host,
		Port:           port,
		User:           user,
		PrivateKeyPath: privateKeyPath,
		TargetHost:     "localhost", // Default to localhost
		logger:         log.New(os.Stdout, "[TUNNEL] ", log.LstdFlags),
		stopPing:       make(chan struct{}),
	}
}

// Connect establishes an SSH connection to the tunnel server
func (c *TunnelClient) Connect() error {
	var authMethods []ssh.AuthMethod

	// If private key path is provided, use it
	if c.PrivateKeyPath != "" {
		c.logger.Printf("Reading private key from %s", c.PrivateKeyPath)
		privateKeyBytes, err := os.ReadFile(c.PrivateKeyPath)
		if err != nil {
			return fmt.Errorf("failed to read private key: %v", err)
		}

		c.logger.Printf("Parsing private key")
		signer, err := ssh.ParsePrivateKey(privateKeyBytes)
		if err != nil {
			return fmt.Errorf("failed to parse private key: %v", err)
		}
		authMethods = append(authMethods, ssh.PublicKeys(signer))
	}

	// Try to use SSH agent
	if socket := os.Getenv("SSH_AUTH_SOCK"); socket != "" {
		c.logger.Printf("Attempting to use SSH agent at %s", socket)
		conn, err := net.Dial("unix", socket)
		if err != nil {
			c.logger.Printf("Failed to connect to SSH agent: %v", err)
		} else {
			agentClient := agent.NewClient(conn)
			authMethods = append(authMethods, ssh.PublicKeysCallback(agentClient.Signers))
		}
	}

	if len(authMethods) == 0 {
		return fmt.Errorf("no authentication methods available")
	}

	config := &ssh.ClientConfig{
		User:            c.User,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	addr := fmt.Sprintf("%s:%d", c.Host, c.Port)
	c.logger.Printf("Connecting to SSH server at %s", addr)
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return fmt.Errorf("failed to connect to SSH server: %v", err)
	}

	c.sshClient = client
	c.logger.Printf("Successfully connected to SSH server")
	return nil
}

// startPingRoutine starts a goroutine that sends periodic pings to keep the connection alive
func (c *TunnelClient) startPingRoutine() {
	ticker := time.NewTicker(30 * time.Second)
	reconnectTicker := time.NewTicker(5 * time.Second)
	isConnected := true

	go func() {
		defer ticker.Stop()
		defer reconnectTicker.Stop()

		for {
			select {
			case <-c.stopPing:
				return
			case <-ticker.C:
				if c.sshChannel != nil && isConnected {
					c.logger.Printf("Sending ping to server")
					ok, err := c.sshChannel.SendRequest("ping", true, nil)
					if err != nil {
						c.logger.Printf("Failed to send ping: %v", err)
						isConnected = false
						continue
					}
					if !ok {
						c.logger.Printf("Server rejected ping, target port may be inaccessible")
						isConnected = false
					}
				}
			case <-reconnectTicker.C:
				if !isConnected {
					c.logger.Printf("Attempting to reconnect...")
					if err := c.reconnect(); err != nil {
						c.logger.Printf("Failed to reconnect: %v", err)
					} else {
						c.logger.Printf("Successfully reconnected")
						isConnected = true
					}
				}
			}
		}
	}()
}

// reconnect attempts to reestablish the connection and tunnel
func (c *TunnelClient) reconnect() error {
	// Close existing connections
	if c.sshChannel != nil {
		c.sshChannel.Close()
		c.sshChannel = nil
	}
	if c.sshClient != nil {
		c.sshClient.Close()
		c.sshClient = nil
	}

	// Reconnect
	if err := c.Connect(); err != nil {
		return fmt.Errorf("failed to reconnect SSH: %v", err)
	}

	// Recreate tunnel
	if err := c.CreateTunnelWithRemoteHost(c.TargetHost, c.TargetPort, c.SubdomainSeed); err != nil {
		return fmt.Errorf("failed to recreate tunnel: %v", err)
	}

	return nil
}

// CreateTunnelWithRemoteHost requests a new tunnel from the server with a specific target host and port
func (c *TunnelClient) CreateTunnelWithRemoteHost(targetHost string, targetPort int, subdomainSeed string) error {
	if c.sshClient == nil {
		return fmt.Errorf("not connected to SSH server")
	}

	if subdomainSeed == "" {
		return fmt.Errorf("subdomain is required")
	}

	// Verify we can connect to the target host and port
	targetAddr := fmt.Sprintf("%s:%d", targetHost, targetPort)
	conn, err := net.DialTimeout("tcp", targetAddr, 5*time.Second)
	if err != nil {
		return fmt.Errorf("cannot connect to target address %s: %v", targetAddr, err)
	}
	conn.Close()

	c.TargetHost = targetHost
	c.TargetPort = targetPort
	c.SubdomainSeed = subdomainSeed

	c.logger.Printf("Opening tunnel channel")
	channel, requests, err := c.sshClient.OpenChannel("tunnel", nil)
	if err != nil {
		return fmt.Errorf("failed to open tunnel channel: %v", err)
	}

	go ssh.DiscardRequests(requests)

	type tunnelRequest struct {
		TargetPort    uint32
		TargetHost    string
		SubdomainSeed string
	}

	req := tunnelRequest{
		TargetPort:    uint32(targetPort),
		TargetHost:    targetHost,
		SubdomainSeed: subdomainSeed,
	}

	c.logger.Printf("Sending tunnel request (target: %s:%d, subdomain: %s)",
		targetHost, targetPort, subdomainSeed)
	ok, err := channel.SendRequest("tunnel-request", true, ssh.Marshal(req))
	if err != nil || !ok {
		channel.Close()
		return fmt.Errorf("failed to send tunnel request: %v", err)
	}

	c.sshChannel = channel
	c.logger.Printf("Tunnel established successfully")

	// Start ping routine
	c.startPingRoutine()

	return nil
}

// CreateTunnel requests a new tunnel from the server
func (c *TunnelClient) CreateTunnel(targetPort int, subdomainSeed string) error {
	if subdomainSeed == "" {
		return fmt.Errorf("subdomain is required")
	}
	return c.CreateTunnelWithRemoteHost("localhost", targetPort, subdomainSeed)
}

// Close closes the tunnel and SSH connection
func (c *TunnelClient) Close() error {
	// Stop ping routine
	if c.stopPing != nil {
		close(c.stopPing)
	}

	if c.sshChannel != nil {
		c.logger.Printf("Closing tunnel channel")
		c.sshChannel.Close()
		c.sshChannel = nil
	}

	if c.sshClient != nil {
		c.logger.Printf("Closing SSH connection")
		err := c.sshClient.Close()
		c.sshClient = nil
		if err != nil {
			return fmt.Errorf("failed to close SSH connection: %v", err)
		}
	}

	c.logger.Printf("Tunnel client closed successfully")
	return nil
}
