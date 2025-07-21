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

	fmt.Println("Initializing npm and installing dependencies...")
	runCmd("npm", []string{"init", "-y"}, serverDir)

	// Install all required dependencies
	dependencies := []string{
		"express",
		"multer",
		"ejs",
		"express-ejs-layouts",
		"bcrypt",
		"better-sqlite3",
		"express-rate-limit",
		"express-session",
		"validator",
	}

	runCmd("npm", append([]string{"install"}, dependencies...), serverDir)

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
