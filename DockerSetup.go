package main

import (
        "fmt"
        "log"
        "os"
        "os/exec"
        "os/user"
        "strings"
        "time"
)

func main() {
        fmt.Println("Starting GoSpoof Docker Setup …")
        if err := fullInstall(); err != nil {
                log.Fatalf("Setup failed: %v", err)
        }
        if exec.Command("docker", "info").Run() == nil {
                fmt.Println("🎉 Docker is READY (non-sudo).")
                return
        }
        if exec.Command("sudo", "docker", "info").Run() == nil {
                fmt.Println("✅ Docker is up. If non-sudo fails, open a new terminal or run `newgrp docker`.")
                return
        }
        log.Fatal("❌ Daemon unhealthy — check `journalctl -xeu containerd` and `journalctl -xeu docker`.")
}

func fullInstall() error {
        u := pickUser()

        _ = run("sudo", "rm", "-f", "/etc/apt/sources.list.d/docker.list", "/etc/apt/sources.list.d/docker*.list")
        must("sudo", "apt-get", "update", "-y")

        must("sudo", "apt-get", "install", "-y", "ca-certificates", "curl", "gnupg", "lsb-release", "acl")

        if run("sudo", "apt-get", "install", "-y", "docker.io", "containerd", "runc") != nil {
                fmt.Println("⚠  docker.io path failed; setting up Docker CE repo …")
                if err := installDockerCE(); err != nil {
                        return fmt.Errorf("both docker.io and CE repo installs failed: %w", err)
                }
        }

        // containerd sane config
        must("sudo", "mkdir", "-p", "/etc/containerd")
        sh(`containerd config default | sed 's/SystemdCgroup = false/SystemdCgroup = true/' | sudo tee /etc/containerd/config.toml >/dev/null`)

        sh(`printf 'overlay\nbr_netfilter\n' | sudo tee /etc/modules-load.d/containerd.conf >/dev/null`)
        _ = run("sudo", "modprobe", "overlay")
        _ = run("sudo", "modprobe", "br_netfilter")
        sh(`cat >/tmp/99-containerd.conf <<'EOF'
net.ipv4.ip_forward = 1
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1
EOF
sudo mv /tmp/99-containerd.conf /etc/sysctl.d/99-containerd.conf
sudo sysctl --system >/dev/null`)

        _ = run("sudo", "systemctl", "stop", "docker")
        _ = run("sudo", "systemctl", "stop", "containerd")
        must("sudo", "systemctl", "daemon-reload")
        must("sudo", "systemctl", "enable", "--now", "containerd")
        if err := waitActive("containerd", 30*time.Second); err != nil {
                return fmt.Errorf("containerd failed to become active: %w", err)
        }

        //docker group
        if run("getent", "group", "docker") != nil {
                must("sudo", "groupadd", "--system", "docker")
        }
        _ = run("sudo", "usermod", "-aG", "docker", u)

        //detect packaging:
        socketOK := unitExists("docker.socket")
        sysvShim := isSysVShim("docker.service")

        if socketOK && !sysvShim {
                sh("sudo mkdir -p /etc/systemd/system/docker.socket.d")
                sh(`printf "[Socket]\nSocketGroup=docker\nSocketMode=0660\n" | sudo tee /etc/systemd/system/docker.socket.d/group.conf >/dev/null`)
                _ = run("sudo", "rm", "-f", "/run/docker.sock", "/var/run/docker.sock")
                must("sudo", "systemctl", "daemon-reload")
                must("sudo", "systemctl", "enable", "--now", "docker.socket")

                if err := retry(5, 2*time.Second, func() error {
                        _ = run("sudo", "systemctl", "start", "docker")
                        return waitActive("docker", 8*time.Second)
                }); err != nil {
                        _ = run("sudo", "mv", "/etc/docker/daemon.json", "/etc/docker/daemon.json.bak")
                        _ = run("sudo", "systemctl", "restart", "docker.socket")
                        if err2 := retry(3, 2*time.Second, func() error {
                                _ = run("sudo", "systemctl", "restart", "docker")
                                return waitActive("docker", 8*time.Second)
                        }); err2 != nil {
                                return fmt.Errorf("docker failed to start (socket mode): %w", err)
                        }
                }
        } else {
                _ = run("sudo", "systemctl", "stop", "docker.socket")
                _ = run("sudo", "systemctl", "disable", "docker.socket")
                _ = run("sudo", "rm", "-rf", "/etc/systemd/system/docker.socket.d")
                must("sudo", "systemctl", "daemon-reload")

                if err := retry(5, 2*time.Second, func() error {
                        _ = run("sudo", "systemctl", "enable", "--now", "docker")
                        _ = run("sudo", "systemctl", "restart", "docker")
                        return waitActive("docker", 8*time.Second)
                }); err != nil {
                        _ = run("sudo", "mv", "/etc/docker/daemon.json", "/etc/docker/daemon.json.bak")
                        if err2 := retry(3, 2*time.Second, func() error {
                                _ = run("sudo", "systemctl", "restart", "docker")
                                return waitActive("docker", 8*time.Second)
                        }); err2 != nil {
                                return fmt.Errorf("docker failed to start (service mode): %w", err)
                        }
                }
        }

        if err := waitForFile("/var/run/docker.sock", 20*time.Second); err == nil {
                _ = run("sudo", "chgrp", "docker", "/var/run/docker.sock")
                _ = run("sudo", "chmod", "660", "/var/run/docker.sock")
                _ = run("sudo", "setfacl", "-m", fmt.Sprintf("u:%s:rw,m::rw", u), "/var/run/docker.sock")
        }

        if err := run("sudo", "docker", "info"); err != nil {
                return fmt.Errorf("daemon unhealthy after start")
        }
        return nil
}


func installDockerCE() error {
        must("sudo", "install", "-m", "0755", "-d", "/etc/apt/keyrings")
        sh(`curl -fsSL https://download.docker.com/linux/debian/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg`)
        must("sudo", "chmod", "a+r", "/etc/apt/keyrings/docker.gpg")
        code := osCodename()
        repo := fmt.Sprintf(
                `deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian %s stable`,
                code,
        )
        sh(`echo "` + repo + `" | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null`)
        must("sudo", "apt-get", "update", "-y")
        return run("sudo", "apt-get", "install", "-y",
                "docker-ce", "docker-ce-cli", "containerd.io", "docker-buildx-plugin", "docker-compose-plugin",
        )
}

func pickUser() string {
        if su := os.Getenv("SUDO_USER"); su != "" {
                return su
        }
        if u := os.Getenv("USER"); u != "" {
                return u
        }
        if u, err := user.Current(); err == nil {
                return u.Username
        }
        return "root"
}

func osCodename() string {
        out, _ := exec.Command("bash", "-lc", `. /etc/os-release 2>/dev/null; echo "${VERSION_CODENAME:-}"`).Output()
        code := strings.TrimSpace(string(out))
        if code == "" {
                o2, _ := exec.Command("bash", "-lc", "lsb_release -cs 2>/dev/null || true").Output()
                code = strings.TrimSpace(string(o2))
        }
        if code == "" || strings.Contains(code, "kali") {
                return "bookworm"
        }
        return code
}

func unitExists(name string) bool {
        return exec.Command("bash", "-lc", "systemctl cat "+name+" >/dev/null 2>&1").Run() == nil
}

func isSysVShim(unit string) bool {
        cmd := exec.Command("bash", "-lc", "systemctl status "+unit+" 2>&1 | grep -qi 'systemd-sysv'")
        return cmd.Run() == nil
}

func retry(n int, pause time.Duration, f func() error) error {
        var err error
        for i := 0; i < n; i++ {
                if err = f(); err == nil {
                        return nil
                }
                time.Sleep(pause)
        }
        return err
}

func waitActive(name string, timeout time.Duration) error {
        deadline := time.Now().Add(timeout)
        for time.Now().Before(deadline) {
                if exec.Command("systemctl", "is-active", "--quiet", name).Run() == nil {
                        return nil
                }
                time.Sleep(500 * time.Millisecond)
        }
        _ = run("systemctl", "status", "--no-pager", "-l", name)
        return fmt.Errorf("%s not active after %s", name, timeout)
}

func waitForFile(path string, timeout time.Duration) error {
        deadline := time.Now().Add(timeout)
        for time.Now().Before(deadline) {
                if _, err := os.Stat(path); err == nil {
                        return nil
                }
                time.Sleep(400 * time.Millisecond)
        }
        return fmt.Errorf("%s not found after %s", path, timeout)
}

func run(cmd string, args ...string) error {
        c := exec.Command(cmd, args...)
        c.Stdout, c.Stderr = os.Stdout, os.Stderr
        return c.Run()
}
func must(cmd string, args ...string) { if err := run(cmd, args...); err != nil { log.Fatalf("Failed: %s %v", cmd, args) } }
func sh(s string)                      { _ = exec.Command("bash", "-lc", s).Run() }
func shMust(s string) {
        c := exec.Command("bash", "-lc", s); c.Stdout, c.Stderr = os.Stdout, os.Stderr
        if err := c.Run(); err != nil { log.Fatalf("Failed: %s", s) }
}
