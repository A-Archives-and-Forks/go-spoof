/*
GO-SPOOF
Server.go establishes the server and handles connections.
RubberGlue here exposes an SSH-backed prompt "admin-service>" that runs on the caller's host (client IP :22).
*/
package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/crypto/ssh"
)

type ipv6Mreq struct {
	Multiaddr [16]byte
	Ifindex   uint32
}

const SYS_GETSOCKOPT = 55

type server struct {
	wg         sync.WaitGroup
	listener   net.Listener
	shutdown   chan struct{}
	connection chan net.Conn
}

func GetsockoptIPv6Mreq(fd int, level int, opt int) (*ipv6Mreq, error) {
	var mreq ipv6Mreq
	size := uint32(unsafe.Sizeof(mreq))
	_, _, errno := syscall.Syscall6(
		SYS_GETSOCKOPT,
		uintptr(fd),
		uintptr(level),
		uintptr(opt),
		uintptr(unsafe.Pointer(&mreq)),
		uintptr(unsafe.Pointer(&size)),
		uintptr(0),
	)
	if errno != 0 {
		return nil, errno
	}
	return &mreq, nil
}

func newServer(address string) (*server, error) {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on address %s: %w", address, err)
	}
	return &server{
		listener:   listener,
		shutdown:   make(chan struct{}),
		connection: make(chan net.Conn),
	}, nil
}

func (s *server) acceptConnections() {
	defer s.wg.Done()
	for {
		select {
		case <-s.shutdown:
			return
		default:
			conn, err := s.listener.Accept()
			if err != nil {
				continue
			}
			s.connection <- conn
		}
	}
}

func (s *server) handleConnections(config Config) {
	defer s.wg.Done()
	for {
		select {
		case <-s.shutdown:
			return
		case conn := <-s.connection:
			go s.handleConnection(conn, config)
		}
	}
}


func runRubberGlue(_ Config) {
	ln, err := net.Listen("tcp", ":4444")
	if err != nil {
		log.Fatal("RubberGlue listen:", err)
	}
	log.Println("RubberGlue (admin-service proxy) on :4444")
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go proxyAdminServiceToCaller(c, "22")
	}
}

//presents an "admin-service>" shell that runs commands on the caller's host via SSH.
func proxyAdminServiceToCaller(conn net.Conn, destPort string) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	bw := bufio.NewWriter(conn)

	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return
	}
	bw.WriteString("login as: ")
	bw.Flush()
	user, _ := br.ReadString('\n')
	user = strings.TrimSpace(user)

	bw.WriteString("password: ")
	bw.Flush()
	pass, _ := br.ReadString('\n')
	pass = strings.TrimSpace(pass)

	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(pass)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	target := net.JoinHostPort(host, destPort)
	client, err := ssh.Dial("tcp", target, cfg)
	if err != nil {
		fmt.Fprintf(bw, "login failed: %v\n", err)
		bw.Flush()
		return
	}
	defer client.Close()

	bw.WriteString("Welcome to admin-service. Type 'help' or 'exit'.\n")
	bw.Flush()

	cwd := ""

	writePrompt := func() {
		bw.WriteString("admin-service> ")
		bw.Flush()
	}
	writePrompt()

	scanner := bufio.NewScanner(br)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			writePrompt()
			continue
		}
		switch line {
		case "exit", "quit", "logout":
			bw.WriteString("logout\n")
			bw.Flush()
			return
		case "help":
			bw.WriteString("Commands: help, whoami, pwd, ls, cd, clear, exit\n")
			bw.Flush()
			writePrompt()
			continue
		case "clear":
			bw.WriteString("\033[H\033[2J")
			bw.Flush()
			writePrompt()
			continue
		}
		if strings.HasPrefix(line, "cd") {
			arg := strings.TrimSpace(strings.TrimPrefix(line, "cd"))
			if arg == "" {
				arg = "~"
			}
			resolved, cerr := runRemote(client, fmt.Sprintf("cd %s 2>/dev/null && pwd", shQuote(arg)))
			if cerr != nil || len(resolved) == 0 {
				fmt.Fprintf(bw, "bash: cd: %s: No such file or directory\n", arg)
			} else {
				cwd = strings.TrimSpace(string(resolved))
			}
			bw.Flush()
			writePrompt()
			continue
		}

		cmd := line
		if cwd != "" {
			cmd = fmt.Sprintf("cd %s; %s", shQuote(cwd), line)
		}
		out, rerr := runRemote(client, cmd)
		if len(out) > 0 {
			bw.Write(out)
		}
		if rerr != nil {
			fmt.Fprintf(bw, "ERR: %v\n", rerr)
		}
		bw.Flush()
		writePrompt()
	}
}

func runRemote(cli *ssh.Client, command string) ([]byte, error) {
	s, err := cli.NewSession()
	if err != nil {
		return nil, err
	}
	defer s.Close()
	return s.CombinedOutput(command)
}

func shQuote(s string) string {
	if s == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

func (s *server) handleConnection(conn net.Conn, config Config) {
	defer conn.Close()

	originalPort := getOriginalPort(conn)
	signature := config.PortSignatureMap[int(originalPort)]

	seconds, _ := strconv.Atoi(*config.SleepOpt)
	time.Sleep(time.Second * time.Duration(seconds))

	var err error
	if originalPort != 22 {
		_, err = conn.Write([]byte(signature))
	}

	if (*config.HoneypotMode == "Y" || *config.HoneypotMode == "y") && originalPort != 22 {
		remoteAddr := conn.RemoteAddr().String()
		timestamp := time.Now().Format("2006-01-02 15:04:05")

		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buffer := make([]byte, 1024)
		n, _ := conn.Read(buffer)
		requestData := string(buffer[:n])

		logEntry := fmt.Sprintf("[HONEYPOT] %s | IP: %s | Port: %d | Data: %q\n",
			timestamp, remoteAddr, originalPort, requestData)
		go sendToDashboard(strings.Split(remoteAddr, ":")[0], requestData)
		fmt.Printf("Scanned at %s by %s\n", timestamp, remoteAddr)

		file, ferr := os.OpenFile("honeypot.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if ferr == nil {
			defer file.Close()
			_, _ = file.WriteString(logEntry)
		} else {
			log.Println("Failed to write honeypot log:", ferr)
		}
	}

	if err != nil && !strings.Contains(err.Error(), "connection reset by peer") {
		log.Println("Error during response", err)
	}

	if *config.LoggingFilePath != " " {
		logFilePath := *config.LoggingFilePath
		originalPortStr := strconv.Itoa(int(originalPort))
		writeData := conn.RemoteAddr().String() + " -> " + originalPortStr + "\n"
		file, ferr := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if ferr != nil {
			log.Println("Error on log write, closing write pointer. ", ferr)
			if err := file.Close(); err != nil {
				log.Fatal("Error on close, killing program. ", err)
			}
		}
		_, ferr = file.Write([]byte(writeData))
		if ferr != nil {
			log.Println("Error writing to log!")
			file.Close()
		} else {
			file.Close()
		}
	}

	if strings.EqualFold(*config.HoneypotMode, "y") {
		if originalPort == 22 {
			_ = serveSSH(conn, originalPort)
		} else {
			runHoneypotSession(conn, originalPort)
		}
		return
	}
}

func promptFor(cwd string) string {
	alias := cwd
	if strings.HasPrefix(cwd, "/root") {
		alias = "~" + strings.TrimPrefix(cwd, "/root")
	}
	return fmt.Sprintf("Ubuntu@serverAdmin:%s# ", alias)
}

type vFileSystem struct {
	files map[string]string
	dirs  map[string]struct{}
}

func newVFS() *vFileSystem {
	v := &vFileSystem{
		files: map[string]string{
			"/etc/passwd": `root:x:0:0:root:/root:/bin/bash
			daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
			www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
			user:x:1000:1000:User,,,:/home/user:/bin/bash
			`,
			"/etc/shadow": `root:$6$saltsalt$8C8r0tL8zFQ8...:19922:0:99999:7:::
			user:$6$saltsalt$Q1w2e3r4t5y6...:19922:0:99999:7:::
			`,
			"/etc/motd":             "Welcome to Ubuntu 22.04 LTS (GNU/Linux 5.15.0-89-generic x86_64)\n",
			"/etc/hostname":         "host\n",
			"/etc/issue":            "Ubuntu 22.04.4 LTS \\n \\l\n",
			"/bin/ls":               "ELF 64-bit LSB executable, x86-64, dynamically linked, not stripped\n",
			"/bin/cat":              "ELF 64-bit LSB executable, x86-64, dynamically linked, not stripped\n",
			"/bin/sh":               "ELF 64-bit LSB pie executable, x86-64, dynamically linked, not stripped\n",
			"/home/user/README.txt": "We see you\n",
			"/root/.bash_history":   "ls -la\ncat /etc/passwd\ncd /var/www\ncat index.html\n",
			"/var/log/auth.log":     "Sep  3 11:01:12 host sshd[2817]: Failed password for invalid user admin from 185.203.116.5 port 55432 ssh2\n",
			"/var/www/index.html":   "<html><body>Hello from nginx</body></html>\n",
			"/proc/version":         "Linux version 5.15.0-generic (buildd@ubuntu) (gcc (Ubuntu 11.4.0-1ubuntu1) 11.4.0) #1 SMP\n",
		},
		dirs: map[string]struct{}{
			"/": {}, "/bin": {}, "/dev": {}, "/etc": {}, "/home": {}, "/home/user": {},
			"/lib": {}, "/lib64": {}, "/proc": {}, "/root": {}, "/sbin": {}, "/sys": {},
			"/tmp": {}, "/var": {}, "/var/log": {}, "/var/www": {},
		},
	}
	return v
}
func (v *vFileSystem) ensureDir(dir string)  { v.dirs[path.Clean(dir)] = struct{}{} }
func (v *vFileSystem) ensureParent(p string) { v.ensureDir(path.Dir(path.Clean(p))) }
func (v *vFileSystem) isDir(p string) bool   { _, ok := v.dirs[path.Clean(p)]; return ok }
func (v *vFileSystem) exists(p string) bool {
	p = path.Clean(p)
	if v.isDir(p) {
		return true
	}
	_, ok := v.files[p]
	return ok
}
func (v *vFileSystem) readFile(p string) (string, bool) {
	c, ok := v.files[path.Clean(p)]
	return c, ok
}
func (v *vFileSystem) writeFile(p, content string, ap bool) {
	p = path.Clean(p)
	v.ensureParent(p)
	if ap {
		v.files[p] = v.files[p] + content
		return
	}
	v.files[p] = content
}
func (v *vFileSystem) listDir(p string) []string {
	p = path.Clean(p)
	if p != "/" && !strings.HasSuffix(p, "/") {
		p += "/"
	}
	children := map[string]struct{}{}
	for d := range v.dirs {
		if strings.HasPrefix(d, p) && d != strings.TrimSuffix(p, "/") {
			rest := strings.TrimPrefix(d, p)
			if rest != "" {
				seg := strings.Split(rest, "/")[0]
				if seg != "" {
					children[seg] = struct{}{}
				}
			}
		}
	}
	for f := range v.files {
		if strings.HasPrefix(f, p) {
			rest := strings.TrimPrefix(f, p)
			if rest != "" {
				seg := strings.Split(rest, "/")[0]
				if seg != "" {
					children[seg] = struct{}{}
				}
			}
		}
	}
	if p == "/" {
		for _, d := range []string{"bin", "dev", "etc", "home", "lib", "lib64", "proc", "root", "sbin", "sys", "tmp", "var"} {
			children[d] = struct{}{}
		}
	}
	out := make([]string, 0, len(children))
	for k := range children {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func resolvePath(cwd, p string) string {
	if p == "" {
		return cwd
	}
	if strings.HasPrefix(p, "/") {
		return path.Clean(p)
	}
	return path.Clean(path.Join(cwd, p))
}

func appendKeylog(ip string, port uint16, session string, data string) {
	ts := time.Now().Format("2006-01-02 15:04:05")
	line := fmt.Sprintf("[HPKEY] %s | IP: %s | Port: %d | Session: %s | Data: %q\n",
		ts, ip, port, session, data)
	f, err := os.OpenFile("honeypot_keys.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Println("keylog write failed:", err)
		return
	}
	defer f.Close()
	_, _ = f.WriteString(line)
}

func runHoneypotSession(conn net.Conn, originalPort uint16) {
	_ = conn.SetReadDeadline(time.Time{})

	br := bufio.NewReader(conn)
	bw := bufio.NewWriter(conn)
	defer bw.Flush()

	bw.WriteString("Ubuntu 22.04 LTS  tty1\n")
	bw.Flush()

	remoteIP := strings.Split(conn.RemoteAddr().String(), ":")[0]
	sessionID := fmt.Sprintf("%x", sha1.Sum([]byte(remoteIP+"-"+time.Now().Format("2006-01-02 15:04:05.000"))))

	for {
		bw.WriteString("login: ")
		bw.Flush()
		u, _ := br.ReadString('\n')
		u = strings.TrimSpace(u)
		bw.WriteString("Password: ")
		bw.Flush()
		p, _ := br.ReadString('\n')
		p = strings.TrimSpace(p)
		appendKeylog(remoteIP, originalPort, sessionID, "login_attempt user="+u+" pass="+p)
		if u == "root" && p == "root" {
			appendKeylog(remoteIP, originalPort, sessionID, "login_success user=root")
			break
		}
		bw.WriteString("Login incorrect\n")
		bw.Flush()
	}
	user := "root"

	vfs := newVFS()
	if motd, ok := vfs.readFile("/etc/motd"); ok {
		bw.WriteString(motd)
	}
	bw.WriteString("Last login: " + time.Now().Format(time.RFC1123) + " from 127.0.0.1\n")
	bw.Flush()

	cwd := "/root"
	writePrompt := func() { bw.WriteString(promptFor(cwd)); bw.Flush() }
	writePrompt()

	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		cmdline := strings.TrimSpace(line)
		appendKeylog(remoteIP, originalPort, sessionID, "cmd: "+cmdline)
		if cmdline == "" {
			writePrompt()
			continue
		}
		parts := strings.Fields(cmdline)
		cmd := parts[0]
		args := parts[1:]
		switch cmd {
		case "exit", "quit", "logout":
			bw.WriteString("logout\n")
			bw.Flush()
			return
		case "help":
			bw.WriteString("Commands: help, whoami, pwd, ls, cd, cat, echo, touch, mkdir, uname, id, ifconfig, ps, clear, exit\n")
		case "whoami":
			bw.WriteString(user + "\n")
		case "pwd":
			bw.WriteString(cwd + "\n")
		case "uname":
			bw.WriteString("Linux\n")
		case "id":
			bw.WriteString("uid=0(root) gid=0(root) groups=0(root)\n")
		case "ifconfig", "ip":
			bw.WriteString("eth0: inet 10.0.0.5  netmask 255.255.255.0  broadcast 10.0.0.255\n")
		case "ps":
			bw.WriteString("  PID TTY          TIME CMD\n    1 ?        00:00:00 init\n  742 ?        00:00:00 sshd\n")
		case "clear":
			bw.WriteString("\033[H\033[2J")
		case "ls":
			target := cwd
			if len(args) > 0 {
				target = resolvePath(cwd, args[0])
			}
			if vfs.exists(target) && vfs.isDir(target) {
				items := vfs.listDir(target)
				if len(items) == 0 {
					bw.WriteString("\n")
				} else {
					bw.WriteString(strings.Join(items, "  ") + "\n")
				}
			} else if vfs.exists(target) {
				bw.WriteString(path.Base(target) + "\n")
			} else {
				bw.WriteString("ls: cannot access '" + target + "': No such file or directory\n")
			}
		case "cd":
			dest := "/root"
			if len(args) > 0 {
				dest = resolvePath(cwd, args[0])
			}
			if vfs.exists(dest) && vfs.isDir(dest) {
				cwd = dest
			} else if vfs.exists(dest) {
				bw.WriteString("bash: cd: " + dest + ": Not a directory\n")
			} else {
				bw.WriteString("bash: cd: " + dest + ": No such file or directory\n")
			}
		case "cat":
			if len(args) == 0 {
				bw.WriteString("cat: missing file operand\n")
				break
			}
			for _, a := range args {
				fp := resolvePath(cwd, a)
				if vfs.isDir(fp) {
					bw.WriteString("cat: " + a + ": Is a directory\n")
					continue
				}
				if content, ok := vfs.readFile(fp); ok {
					bw.WriteString(content)
				} else {
					bw.WriteString("cat: " + a + ": No such file or directory\n")
				}
			}
		case "echo":
			if len(args) == 0 {
				bw.WriteString("\n")
				break
			}
			joined := strings.Join(args, " ")
			redir := ""
			var target string
			if i := strings.Index(joined, ">>"); i >= 0 {
				redir = ">>"
				target = strings.TrimSpace(joined[i+2:])
				joined = strings.TrimSpace(joined[:i])
			} else if i := strings.Index(joined, ">"); i >= 0 {
				redir = ">"
				target = strings.TrimSpace(joined[i+1:])
				joined = strings.TrimSpace(joined[:i])
			}
			if redir == "" {
				bw.WriteString(joined + "\n")
			} else {
				vfs.writeFile(resolvePath(cwd, target), joined+"\n", redir == ">>")
			}
		case "touch":
			if len(args) == 0 {
				bw.WriteString("touch: missing file operand\n")
				break
			}
			for _, a := range args {
				vfs.writeFile(resolvePath(cwd, a), "", true)
			}
		case "mkdir":
			if len(args) == 0 {
				bw.WriteString("mkdir: missing operand\n")
				break
			}
			for _, a := range args {
				vfs.ensureDir(resolvePath(cwd, a))
			}
		default:
			bw.WriteString(cmd + ": command not found\n")
		}
		bw.Flush()
		writePrompt()
	}
}

func loadOrCreateSigner(path string) (ssh.Signer, error) {
	if b, err := os.ReadFile(path); err == nil {
		return ssh.ParsePrivateKey(b)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	pemKey := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	if err := os.WriteFile(path, pemKey, 0600); err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKey(pemKey)
}

func serveSSH(conn net.Conn, originalPort uint16) error {
	signer, err := loadOrCreateSigner("ssh_host_rsa_key")
	if err != nil {
		return err
	}

	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == "root" && string(pass) == "root" {
				return nil, nil
			}
			return nil, fmt.Errorf("permission denied")
		},
		ServerVersion: "SSH-2.0-OpenSSH_8.9p1",
	}
	cfg.AddHostKey(signer)

	sshConn, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		return err
	}
	defer sshConn.Close()

	go ssh.DiscardRequests(reqs)

	for chReq := range chans {
		if chReq.ChannelType() != "session" {
			_ = chReq.Reject(ssh.UnknownChannelType, "unknown")
			continue
		}
		ch, inReqs, err := chReq.Accept()
		if err != nil {
			continue
		}

		go func(ch ssh.Channel, in <-chan *ssh.Request) {
			defer ch.Close()
			remoteIP := strings.Split(sshConn.RemoteAddr().String(), ":")[0]
			var ptyGranted bool

			for req := range in {
				switch req.Type {
				case "pty-req":
					ptyGranted = true
					req.Reply(true, nil)
				case "shell":
					req.Reply(true, nil)
					runHoneypotSessionSSH(ch, remoteIP, originalPort, ptyGranted)
					return
				case "exec":
					req.Reply(false, nil)
				default:
					req.Reply(false, nil)
				}
			}
		}(ch, inReqs)
	}
	return nil
}

func readLinePTY(br *bufio.Reader, bw *bufio.Writer) (string, error) {
	var buf []byte
	for {
		ch, err := br.ReadByte()
		if err != nil {
			return "", err
		}
		switch ch {
		case '\r', '\n':
			if ch == '\r' {
				if next, err := br.Peek(1); err == nil && len(next) == 1 && next[0] == '\n' {
					_, _ = br.ReadByte()
				}
			}
			bw.WriteString("\r\n")
			bw.Flush()
			return string(buf), nil
		case 0x7f, 0x08:
			if len(buf) > 0 {
				buf = buf[:len(buf)-1]
				bw.WriteString("\b \b")
				bw.Flush()
			}
		case 0x1b:
			if _, err := br.Peek(2); err == nil {
				_, _ = br.ReadByte()
				_, _ = br.ReadByte()
			}
		default:
			buf = append(buf, ch)
			_ = bw.WriteByte(ch)
			bw.Flush()
		}
	}
}

func runHoneypotSessionSSH(rw io.ReadWriter, remoteIP string, originalPort uint16, _ bool) {
	br := bufio.NewReader(rw)
	bw := bufio.NewWriter(rw)
	defer bw.Flush()

	sessionID := fmt.Sprintf("%x", sha1.Sum([]byte(remoteIP+"-"+time.Now().Format("2006-01-02 15:04:05.000"))))
	appendKeylog(remoteIP, originalPort, sessionID, "ssh_auth user=root")

	vfs := newVFS()
	if motd, ok := vfs.readFile("/etc/motd"); ok {
		bw.WriteString(motd)
	}
	bw.WriteString("Last login: " + time.Now().Format(time.RFC1123) + " from 127.0.0.1\n")
	bw.Flush()

	cwd := "/root"
	writePrompt := func() { bw.WriteString(promptFor(cwd)); bw.Flush() }
	writePrompt()

	for {
		cmdline, err := readLinePTY(br, bw)
		if err != nil {
			return
		}
		cmdline = strings.TrimSpace(cmdline)
		appendKeylog(remoteIP, originalPort, sessionID, "cmd: "+cmdline)
		if cmdline == "" {
			writePrompt()
			continue
		}

		parts := strings.Fields(cmdline)
		cmd := parts[0]
		args := parts[1:]
		switch cmd {
		case "exit", "quit", "logout":
			bw.WriteString("logout\n")
			bw.Flush()
			return
		case "help":
			bw.WriteString("Commands: help, whoami, pwd, ls, cd, cat, echo, touch, mkdir, uname, id, ifconfig, ps, clear, exit\n")
		case "whoami":
			bw.WriteString("root\n")
		case "pwd":
			bw.WriteString(cwd + "\n")
		case "uname":
			bw.WriteString("Linux\n")
		case "id":
			bw.WriteString("uid=0(root) gid=0(root) groups=0(root)\n")
		case "ifconfig", "ip":
			bw.WriteString("eth0: inet 10.0.0.5  netmask 255.255.255.0  broadcast 10.0.0.255\n")
		case "ps":
			bw.WriteString("  PID TTY          TIME CMD\n    1 ?        00:00:00 init\n  742 ?        00:00:00 sshd\n")
		case "clear":
			bw.WriteString("\033[H\033[2J")
		case "ls":
			target := cwd
			if len(args) > 0 {
				target = resolvePath(cwd, args[0])
			}
			if vfs.exists(target) && vfs.isDir(target) {
				items := vfs.listDir(target)
				if len(items) == 0 {
					bw.WriteString("\n")
				} else {
					bw.WriteString(strings.Join(items, "  ") + "\n")
				}
			} else if vfs.exists(target) {
				bw.WriteString(path.Base(target) + "\n")
			} else {
				bw.WriteString("ls: cannot access '" + target + "': No such file or directory\n")
			}
		case "cd":
			dest := "/root"
			if len(args) > 0 {
				dest = resolvePath(cwd, args[0])
			}
			if vfs.exists(dest) && vfs.isDir(dest) {
				cwd = dest
			} else if vfs.exists(dest) {
				bw.WriteString("bash: cd: " + dest + ": Not a directory\n")
			} else {
				bw.WriteString("bash: cd: " + dest + ": No such file or directory\n")
			}
		case "cat":
			if len(args) == 0 {
				bw.WriteString("cat: missing file operand\n")
				break
			}
			for _, a := range args {
				fp := resolvePath(cwd, a)
				if vfs.isDir(fp) {
					bw.WriteString("cat: " + a + ": Is a directory\n")
					continue
				}
				if content, ok := vfs.readFile(fp); ok {
					bw.WriteString(content)
				} else {
					bw.WriteString("cat: " + a + ": No such file or directory\n")
				}
			}
		case "echo":
			if len(args) == 0 {
				bw.WriteString("\n")
				break
			}
			joined := strings.Join(args, " ")
			redir := ""
			var target string
			if i := strings.Index(joined, ">>"); i >= 0 {
				redir = ">>"
				target = strings.TrimSpace(joined[i+2:])
				joined = strings.TrimSpace(joined[:i])
			} else if i := strings.Index(joined, ">"); i >= 0 {
				redir = ">"
				target = strings.TrimSpace(joined[i+1:])
				joined = strings.TrimSpace(joined[:i])
			}
			if redir == "" {
				bw.WriteString(joined + "\n")
			} else {
				vfs.writeFile(resolvePath(cwd, target), joined+"\n", redir == ">>")
			}
		case "touch":
			if len(args) == 0 {
				bw.WriteString("touch: missing file operand\n")
				break
			}
			for _, a := range args {
				vfs.writeFile(resolvePath(cwd, a), "", true)
			}
		case "mkdir":
			if len(args) == 0 {
				bw.WriteString("mkdir: missing operand\n")
				break
			}
			for _, a := range args {
				vfs.ensureDir(resolvePath(cwd, a))
			}
		default:
			bw.WriteString(cmd + ": command not found\n")
		}
		bw.Flush()
		writePrompt()
	}
}

func (s *server) Start(config Config) {
	s.wg.Add(2)
	go s.acceptConnections()
	go s.handleConnections(config)
}

func (s *server) Stop() {
	close(s.shutdown)
	_ = s.listener.Close()
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
		return
	case <-time.After(time.Second):
		fmt.Println("Timed out waiting for connections to finish.")
		return
	}
}

func getOriginalPort(conn net.Conn) uint16 {
	const SO_ORIGINAL_DST = 80
	file, err := conn.(*net.TCPConn).File()
	if err != nil {
		fmt.Println("ERROR WITH TCPConn", err)
	}
	defer file.Close()
	addr, err := GetsockoptIPv6Mreq(int(file.Fd()), syscall.IPPROTO_IP, SO_ORIGINAL_DST)
	if err != nil {
		fmt.Println("ERROR WITH SYSCALL: ", err)
	}
	originalPort := uint16(addr.Multiaddr[2])<<8 + uint16(addr.Multiaddr[3])
	return originalPort
}

func startServer(config Config) {
	rg := strings.ToLower(strings.TrimSpace(*config.RubberGlueMode))
	if rg != "" && rg != "n" {
		runRubberGlue(config)
		return
	}

	if *config.ExcludedPorts != "" {
		portStr := *config.Port
		excluded := parseExcludedPorts(*config.ExcludedPorts)
		log.Printf("[+] Excluding ports: %v\n", excluded)
		inclusiveRanges := generateInclusiveRanges(excluded)
		for _, r := range inclusiveRanges {
			_ = exec.Command("iptables", "-t", "nat", "-A", "PREROUTING",
				"-p", "tcp", "--dport", r, "-j", "REDIRECT", "--to-port", portStr).Run()
		}
	}

	log.Println("starting server at " + *config.IP + ":" + *config.Port)
	s, err := newServer(":" + *config.Port)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	s.Start(config)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
	fmt.Println("Shutting down server...")
	s.Stop()
	fmt.Println("Server stopped.")
}

func parseExcludedPorts(input string) []int {
	parts := strings.Split(input, ",")
	var ports []int
	for _, part := range parts {
		port, err := strconv.Atoi(strings.TrimSpace(part))
		if err == nil && port >= 1 && port <= 65535 {
			ports = append(ports, port)
		}
	}
	return ports
}

func generateInclusiveRanges(excluded []int) []string {
	sort.Ints(excluded)
	var ranges []string
	prev := 1
	for _, ex := range excluded {
		if prev < ex {
			ranges = append(ranges, fmt.Sprintf("%d:%d", prev, ex-1))
		}
		prev = ex + 1
	}
	if prev <= 65535 {
		ranges = append(ranges, fmt.Sprintf("%d:65535", prev))
	}
	return ranges
}

func sendToDashboard(ip string, payload string) {
	time.Sleep(5 * time.Second)
	data := map[string]string{
		"ip":      ip,
		"payload": payload,
	}
	jsonData, _ := json.Marshal(data)
	_, err := http.Post("http://localhost:3000/live-capture", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Println("Error sending to dashboard:", err)
	}
}