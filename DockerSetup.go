package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
)

func main() {
	fmt.Println("Starting GoSpoof Docker Setup...")

	// Check for Docker
	if !checkCommand("docker") {
		fmt.Println("Docker not found. Installing for Debian/Kali...")
		installDocker()
	} else {
		fmt.Println("✅ Docker is already installed.")
	}
}

func checkCommand(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func runCmd(cmd string, args []string, dir string) {
	c := exec.Command(cmd, args...)
	if dir != "" {
		c.Dir = dir
	}
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	if err := c.Run(); err != nil {
		log.Fatalf("Failed running %s: %v", cmd, err)
	}
}

func installDocker() {
	fmt.Println("[*] Installing Docker CLI fallback...")

	// Try docker-cli (lightweight option)
	runCmd("sudo", []string{"apt", "update"}, "")
	runCmd("sudo", []string{"apt", "install", "-y", "docker-cli", "docker-buildx"}, "")

	if checkCommand("docker") {
		fmt.Println("[+] docker-cli installed and working.")
		return
	}

	fmt.Println("[!] docker-cli not sufficient. Installing full Docker engine...")

	// Full Docker Engine
	runCmd("sudo", []string{"apt", "install", "-y", "ca-certificates", "curl", "gnupg", "lsb-release"}, "")
	runCmd("sudo", []string{"install", "-m", "0755", "-d", "/etc/apt/keyrings"}, "")
	runCmd("bash", []string{
		"-c",
		`curl -fsSL https://download.docker.com/linux/debian/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg`,
	}, "")
	runCmd("bash", []string{
		"-c",
		`echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null`,
	}, "")
	runCmd("sudo", []string{"apt", "update"}, "")
	runCmd("sudo", []string{"apt", "install", "-y", "docker-ce", "docker-ce-cli", "containerd.io", "docker-compose-plugin"}, "")

	// Enable Docker and add user to group
	runCmd("sudo", []string{"systemctl", "enable", "--now", "docker"}, "")
	runCmd("sudo", []string{"usermod", "-aG", "docker", os.Getenv("USER")}, "")

	fmt.Println("[+] Full Docker engine installed and configured.")
}
