package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
)

func main() {
	fmt.Println("Starting GoSpoof WebUI Setup")
	
	if !checkCommand("node") {
		fmt.Println("Node.js not found. Installing...")
		installNode()
	} else {
		fmt.Println("Node.js is installed.")
	}

	if !checkCommand("npm") {
		fmt.Println("npm not found. Please install it manually.")
		return
	} else {
		fmt.Println("npm is installed.")
	}

	// 3. Navigate to Web/Server (relative to repo root)
	serverDir := "Web/Server"
	if _, err := os.Stat(serverDir); os.IsNotExist(err) {
		log.Fatalf("Web/Server directory not found at %s (run this from the repo root)", serverDir)
	}

	// 4. npm init + deps
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

	//create uploads directory if it doesn't exist
	uploadsDir := filepath.Join(serverDir, "uploads")
	if _, err := os.Stat(uploadsDir); os.IsNotExist(err) {
		fmt.Println("Creating uploads directory...")
		if err := os.MkdirAll(uploadsDir, 0o755); err != nil {
			log.Fatalf("Failed to create uploads directory: %v", err)
		}
	}

	//fix permissions
	fmt.Println("Fixing upload directory permissions...")
	runCmd("sudo", []string{"chmod", "-R", "755", uploadsDir}, "")

	//make sure Go is installed, then add YAML dependency to the module in cmd/gospoof and tidy.
	gospoofDir := "cmd/gospoof"
	ensureGoDeps(gospoofDir)

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

func ensureGoDeps(moduleDir string) {
	if _, err := os.Stat(filepath.Join(moduleDir, "go.mod")); os.IsNotExist(err) {
		log.Printf("[warn] %s/go.mod not found. Skipping Go dependency setup.", moduleDir)
		return
	}

	if !checkCommand("go") {
		fmt.Println("Go not found. Installing...")
		installGo() // Debian/Kali-based
	} else {
		fmt.Println("Go is installed.")
	}

	fmt.Println("Adding YAML dependency and tidying module...")
	runCmd("go", []string{"get", "gopkg.in/yaml.v3@v3.0.1"}, moduleDir)
	runCmd("go", []string{"mod", "tidy"}, moduleDir)
}

func installGo() {
	runCmd("sudo", []string{"apt", "update"}, "")
	if err := tryCmd("sudo", []string{"apt", "install", "-y", "golang-go"}, ""); err != nil {
		log.Printf("[info] 'golang-go' not available, trying 'golang'")
		runCmd("sudo", []string{"apt", "install", "-y", "golang"}, "")
	}
}

func runCmd(cmd string, args []string, dir string) {
	c := exec.Command(cmd, args...)
	if dir != "" {
		c.Dir = dir
	}
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	if err := c.Run(); err != nil {
		log.Fatalf("Failed running %s %v (dir=%s): %v", cmd, args, dir, err)
	}
}

func tryCmd(cmd string, args []string, dir string) error {
	c := exec.Command(cmd, args...)
	if dir != "" {
		c.Dir = dir
	}
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	return c.Run()
}