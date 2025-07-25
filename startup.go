package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
)

func main() {
	fmt.Println("Starting GoSpoof WebUI Setup...")

	// 1. Check for node
	if !checkCommand("node") {
		fmt.Println("Node.js not found. Installing...")
		installNode()
	} else {
		fmt.Println("Node.js is installed.")
	}

	// 2. Check for npm
	if !checkCommand("npm") {
		fmt.Println("npm not found. Please install it manually.")
		return
	} else {
		fmt.Println("npm is installed.")
	}

	// 3. Navigate to Web/Server
	serverDir := "Web/Server"
	if _, err := os.Stat(serverDir); os.IsNotExist(err) {
		log.Fatalf("Web/Server directory not found at %s", serverDir)
	}

	// 4. Check for Docker
	if !checkCommand("docker") {
		fmt.Println("Docker not found. Installing for Debian/Kali...")
		installDocker()
	} else {
		fmt.Println("Docker is installed.")
	}

	// 5. Run npm setup
	fmt.Println("Initializing npm and installing dependencies...")
	runCmd("npm", []string{"init", "-y"}, serverDir)

	runCmd("npm", []string{
		"install",
		"express",
		"multer",
		"ejs",
		"express-ejs-layouts",
		"socket.io",
		"bcrypt",
		"better-sqlite3",
		"express-rate-limit",
		"express-session",
		"validator",
	}, serverDir)

	// 6. Set permissions for uploads dir
	fmt.Println("Fixing upload directory permissions...")
	runCmd("sudo", []string{"chmod", "-R", "755", serverDir + "/uploads"}, "")

	fmt.Println("WebUI setup complete.")
}

func checkCommand(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func installNode() {
	runCmd("sudo", []string{"apt", "update"}, "")
	runCmd("sudo", []string{"apt", "install", "-y", "nodejs", "npm"}, "")
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

	// Try to install docker-cli first (lightweight fallback)
	runCmd("sudo", []string{"apt", "update"}, "")
	runCmd("sudo", []string{"apt", "install", "-y", "docker-cli", "docker-buildx"}, "")

	// Check if that was enough
	if checkCommand("docker") {
		fmt.Println("[+] docker-cli installed and working.")
		return
	}

	fmt.Println("[!] docker-cli not sufficient. Installing full Docker engine...")

	// Full Docker Engine for Debian/Kali
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

	// Enable docker
	runCmd("sudo", []string{"systemctl", "enable", "--now", "docker"}, "")
	runCmd("sudo", []string{"usermod", "-aG", "docker", os.Getenv("USER")}, "")
	fmt.Println("[+] Full Docker engine installed.")
}
