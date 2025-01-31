package main

import (
	"flag"
	"fmt"
	fopstunnel "github.com/e-frogg/fops-tunnel/client"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	// Parse command line flags
	host := flag.String("host", "localhost", "Tunnel server host")
	port := flag.Int("port", 2222, "Tunnel server SSH port")
	user := flag.String("user", "tunnel", "SSH user")
	keyPath := flag.String("key", "", "Path to SSH private key (optional if using SSH agent)")
	localPort := flag.Int("local-port", 8080, "Local port to tunnel")
	remoteHost := flag.String("remote-host", "localhost", "Remote host to forward to (e.g., container name in Docker)")
	subdomain := flag.String("subdomain", "", "Subdomain for the tunnel (optional)")
	flag.Parse()

	// Create tunnel client
	client := fopstunnel.NewTunnelClient(*host, *port, *user, *keyPath)

	// Connect to server
	log.Printf("Connecting to tunnel server %s:%d...", *host, *port)
	if err := client.Connect(); err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer client.Close()

	// Create tunnel
	log.Printf("Creating tunnel for %s:%d...", *remoteHost, *localPort)
	if err := client.CreateTunnelWithRemoteHost(*remoteHost, *localPort, *subdomain); err != nil {
		log.Fatalf("Failed to create tunnel: %v", err)
	}

	log.Printf("Tunnel established successfully")
	log.Printf("Port %d on %s is now accessible through the tunnel", *localPort, *remoteHost)

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	fmt.Println("\nShutting down tunnel...")
}
