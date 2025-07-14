/*
GO-SPOOF

Server.go establishes the server and
handles connections.
*/
package main

import (
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

	os.MkdirAll("captures", 0755)
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
				os.WriteFile(fmt.Sprintf("captures/%s.txt", hash), buf[:n], 0644)
				conn.Write(buf[:n]) // reflect back
			}
		}(conn)
	}
}

// honey start
func (s *server) handleConnection(conn net.Conn, config Config) {
	defer conn.Close()

	//init SO_ORIGINAL_DST, doesn't matter what goes in here, just need something for the GetsocketIPv6Mreq function below
	originalPort := getOriginalPort(conn)
	signature := config.PortSignatureMap[int(originalPort)]

	seconds, _ := strconv.Atoi(*config.SleepOpt)
	time.Sleep(time.Second * time.Duration(seconds))

	_, err := conn.Write([]byte(signature))
	if *config.HoneypotMode == "Y" || *config.HoneypotMode == "y" {
		remoteAddr := conn.RemoteAddr().String()
		timestamp := time.Now().Format("2006-01-02 15:04:05")

		// read data sent by client (if any)
		conn.SetReadDeadline(time.Now().Add(2 * time.Second)) // timeout
		buffer := make([]byte, 1024)
		n, _ := conn.Read(buffer)
		requestData := string(buffer[:n])

		// format log entry
		logEntry := fmt.Sprintf(
			"[HONEYPOT] %s | IP: %s | Port: %d | Data: %q\n",
			timestamp,
			remoteAddr,
			originalPort,
			requestData,
		)
		go sendToDashboard(strings.Split(remoteAddr, ":")[0], requestData)

		fmt.Printf("Scanned at %s by %s\n", timestamp, remoteAddr)

		// save to honeypot.log
		file, err := os.OpenFile("honeypot.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err == nil {
			defer file.Close()
			file.WriteString(logEntry)
		} else {
			log.Println("Failed to write honeypot log:", err)
		}
	}

	if err != nil && !strings.Contains(err.Error(), "connection reset by peer") {
		log.Println("Error during response", err)
	}

	//log the connection if logging is enabled
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
}

//end of honey

func (s *server) Start(config Config) {

	s.wg.Add(2)
	go s.acceptConnections()
	go s.handleConnections(config)
}

func (s *server) Stop() {
	close(s.shutdown)
	s.listener.Close()

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
		runRubberGlue(config) //rg server func
		return
	}
	if *config.ExcludedPorts != "" {
		portStr := *config.Port
		excluded := parseExcludedPorts(*config.ExcludedPorts)
		log.Printf("[+] Excluding ports: %v\n", excluded)
		inclusiveRanges := generateInclusiveRanges(excluded)

		for _, r := range inclusiveRanges {
			exec.Command("iptables", "-t", "nat", "-A", "PREROUTING",
				"-p", "tcp", "--dport", r, "-j", "REDIRECT", "--to-port", portStr).Run()
		}
	}

	//need to pass the port we want to host the server on

	log.Println("starting server at " + *config.IP + ":" + *config.Port)
	s, err := newServer(":" + *config.Port)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	s.Start(config)

	// Wait for a SIGINT or SIGTERM signal to gracefully shut down the server
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
