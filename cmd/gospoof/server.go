/*
GO-SPOOF

Server.go establishes the server and
handles connections.
Honeypot and Rubberglue live here for now
*/
package main

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"encoding/json"
	"fmt"
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

func runRubberGlue(config Config) {
	ln, err := net.Listen("tcp", ":4444")
	if err != nil {
		log.Fatal("Failed to start Rubber Glue listener:", err)
	}
	defer ln.Close()

	_ = os.MkdirAll("captures", 0755)
	log.Println("RubberGlue listener on port 4444")

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}

		go func(conn net.Conn) {
			defer conn.Close()
			remoteAddr := conn.RemoteAddr().String()
			timestamp := time.Now().Format("2006-01-02 15:04:05")
			hash := fmt.Sprintf("%x", sha1.Sum([]byte(remoteAddr+"-"+timestamp)))
			log.Println("RubberGlue hit:", remoteAddr, "->", hash)

			buf := make([]byte, 4096)
			n, err := conn.Read(buf)
			if err == nil && n > 0 {
				_ = os.WriteFile(fmt.Sprintf("captures/%s.txt", hash), buf[:n], 0644)
				_, _ = conn.Write(buf[:n]) // reflect back
			}
		}(conn)
	}
}

func (s *server) handleConnection(conn net.Conn, config Config) {
    defer conn.Close()

    originalPort := getOriginalPort(conn)
    signature := config.PortSignatureMap[int(originalPort)]

    seconds, _ := strconv.Atoi(*config.SleepOpt)
    time.Sleep(time.Second * time.Duration(seconds))
    _, err := conn.Write([]byte(signature))

    if *config.HoneypotMode == "Y" || *config.HoneypotMode == "y" {
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

        file, err := os.OpenFile("honeypot.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
        if err == nil {
            defer file.Close()
            _, _ = file.WriteString(logEntry)
        } else {
            log.Println("Failed to write honeypot log:", err)
        }
    }

    if err != nil && !strings.Contains(err.Error(), "connection reset by peer") {
        log.Println("Error during response", err)
    }

    if *config.LoggingFilePath != " " {
        logFilePath := *config.LoggingFilePath

        originalPortStr := strconv.Itoa(int(originalPort))
        writeData := conn.RemoteAddr().String() + " -> " + originalPortStr + "\n"

        file, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
        if err != nil {
            log.Println("Error on log write, closing write pointer. ", err)
            if err := file.Close(); err != nil {
                log.Fatal("Error on close, killing program. ", err)
            }
        }

        _, err = file.Write([]byte(writeData))
        if err != nil {
            log.Println("Error writing to log!")
            file.Close()
        } else {
            file.Close()
        }
    }

    if strings.EqualFold(*config.HoneypotMode, "y") {
        if originalPort == 22 { 
            runHoneypotSession(conn, originalPort)
        }
        return
    }
}

//prompt shows current path
func promptFor(cwd string) string {
	alias := cwd
	if strings.HasPrefix(cwd, "/root") {
		alias = "~" + strings.TrimPrefix(cwd, "/root")
	}
	return fmt.Sprintf("Ubuntu@serverAdmin:%s# ", alias)
}

//VFS start

type vFileSystem struct {
	files map[string]string
	dirs  map[string]struct{}
}

func newVFS() *vFileSystem {
	v := &vFileSystem{
		files: map[string]string{
			//core system files
			"/etc/passwd": `root:x:0:0:root:/root:/bin/bash
			daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
			www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
			user:x:1000:1000:User,,,:/home/user:/bin/bash
			`,
			"/etc/shadow": `root:$6$saltsalt$8C8r0tL8zFQ8...:19922:0:99999:7:::
			user:$6$saltsalt$Q1w2e3r4t5y6...:19922:0:99999:7:::
			`,
			"/etc/motd":     "Welcome to Ubuntu 22.04 LTS (GNU/Linux 5.15.0-89-generic x86_64)\n",
			"/etc/hostname": "host\n",
			"/etc/issue":    "Ubuntu 22.04.4 LTS \\n \\l\n",

			//make /bin look alive
			"/bin/ls":  "ELF 64-bit LSB executable, x86-64, dynamically linked, not stripped\n",
			"/bin/cat": "ELF 64-bit LSB executable, x86-64, dynamically linked, not stripped\n",
			"/bin/sh":  "ELF 64-bit LSB pie executable, x86-64, dynamically linked, not stripped\n",

			//home & root
			"/home/user/README.txt": "We see you\n",
			"/root/.bash_history":   "ls -la\ncat /etc/passwd\ncd /var/www\ncat index.html\n",

			//logs & web bits
			"/var/log/auth.log":   "Sep  3 11:01:12 host sshd[2817]: Failed password for invalid user admin from 185.203.116.5 port 55432 ssh2\n",
			"/var/www/index.html": "<html><body>Hello from nginx</body></html>\n",

			//proc/sys just to look real
			"/proc/version": "Linux version 5.15.0-generic (buildd@ubuntu) (gcc (Ubuntu 11.4.0-1ubuntu1) 11.4.0) #1 SMP\n",
		},
		dirs: map[string]struct{}{
			"/": {}, "/bin": {}, "/dev": {}, "/etc": {}, "/home": {}, "/home/user": {},
			"/lib": {}, "/lib64": {}, "/proc": {}, "/root": {}, "/sbin": {}, "/sys": {},
			"/tmp": {}, "/var": {}, "/var/log": {}, "/var/www": {},
		},
	}
	return v
}
func (v *vFileSystem) ensureDir(dir string) {
	d := path.Clean(dir)
	if d == "" {
		d = "/"
	}
	v.dirs[d] = struct{}{}
}

func (v *vFileSystem) ensureParent(p string) {
	parent := path.Dir(path.Clean(p))
	v.ensureDir(parent)
}

func (v *vFileSystem) isDir(p string) bool {
	p = path.Clean(p)
	_, ok := v.dirs[p]
	return ok
}

func (v *vFileSystem) exists(p string) bool {
	p = path.Clean(p)
	if v.isDir(p) {
		return true
	}
	_, ok := v.files[p]
	return ok
}

func (v *vFileSystem) readFile(p string) (string, bool) {
	p = path.Clean(p)
	c, ok := v.files[p]
	return c, ok
}

func (v *vFileSystem) writeFile(p, content string, appendMode bool) {
	p = path.Clean(p)
	v.ensureParent(p)
	if appendMode {
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

	// gather subdirs
	for d := range v.dirs {
		if strings.HasPrefix(d, p) && d != strings.TrimSuffix(p, "/") {
			rest := strings.TrimPrefix(d, p)
			if rest == "" {
				continue
			}
			seg := strings.Split(rest, "/")[0]
			if seg != "" {
				children[seg] = struct{}{}
			}
		}
	}
	for f := range v.files {
		if strings.HasPrefix(f, p) {
			rest := strings.TrimPrefix(f, p)
			if rest == "" {
				continue
			}
			seg := strings.Split(rest, "/")[0]
			if seg != "" {
				children[seg] = struct{}{}
			}
		}
	}

	//make highest lvl look full even if empty
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

//keystroke/command logging separate file

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

	//shows current path
	cwd := "/root"
	writePrompt := func() { bw.WriteString(promptFor(cwd)); bw.Flush() }
	writePrompt()

	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		cmdline := strings.TrimSpace(line)

		//keylog every command line
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
				fp := resolvePath(cwd, target)
				vfs.writeFile(fp, joined+"\n", redir == ">>")
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
	go func() {
		s.wg.Wait()
		close(done)
	}()

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
	if *config.RubberGlueMode == "Y" || *config.RubberGlueMode == "y" {
		runRubberGlue(config) // rg server func
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

	// graceful shutdown on SIGINT/SIGTERM
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