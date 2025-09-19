package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
)

func main() {
	fmt.Println("Starting GoSpoof Docker Setup...")
	if !ready() {
		fmt.Println("Installing full Docker engine (docker.io)...")
		run("sudo", "apt-get", "update")
		run("sudo", "apt-get", "install", "-y", "docker.io")
		run("sudo", "systemctl", "enable", "--now", "docker")
		run("sudo", "usermod", "-aG", "docker", os.Getenv("USER"))
	}
	if err := exec.Command("docker", "info").Run(); err != nil {
		fmt.Println("Docker installed, but current shell may not have group perms.")
		fmt.Println("Run: `newgrp docker` or log out/in, then try `docker run hello-world`.")
	} else {
		fmt.Println("Docker is ready.")
	}
}

func ready() bool {
	if _, err := exec.LookPath("docker"); err != nil { return false }
	return exec.Command("docker", "info").Run() == nil //confirms daemon is reachable
}

func run(cmd string, args ...string) {
	c := exec.Command(cmd, args...)
	c.Stdout, c.Stderr = os.Stdout, os.Stderr
	if err := c.Run(); err != nil {
		log.Fatalf("Failed: %s %v: %v\n", cmd, args, err)
	}
}
