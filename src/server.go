/*
GO-SPOOF 

Server.go establishes the server and 
handles connections. 

TO-DO
	- ADD THREADPOOL
    - RESPOND WITH THE LIES 
*/
package main

import (
 "fmt"
 "net"
 "os"
 "os/signal"
 "sync"
 "syscall"
 "time"
 "log"
)

type server struct {
 wg         sync.WaitGroup
 listener   net.Listener
 shutdown   chan struct{}
 connection chan net.Conn
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

//THIS IS WHERE THE ACTUAL SPOOFING HAPPENS >:)
func (s *server) handleConnection(conn net.Conn, config Config) {
 defer conn.Close()

 //get the original port (port before iptables redirect)
 const SO_ORIGINAL_DST = 80;
 //fmt.Println(conn.RemoteAddr().String())
 file, err := conn.(*net.TCPConn).File()
 if err != nil {
    fmt.Println("ERROR WITH TCPConn", err)
 }
 defer file.Close()
 addr, err := syscall.GetsockoptIPv6Mreq(int(file.Fd()), syscall.IPPROTO_IP, SO_ORIGINAL_DST)
 if err != nil {
    fmt.Println("ERROR WITH SYSCALL: ", err)
 }

 originalPort := uint16(addr.Multiaddr[2])<<8 + uint16(addr.Multiaddr[3])
 signature := config.PortSignatureMap[int(originalPort)]
 

 _, err = conn.Write([]byte(signature))
 if err != nil {
   log.Println("Error during response", err)
   return
 }


 // ADD WORK HERE
 fmt.Fprintf(conn, "Welcome to my TCP server!\n")
 time.Sleep(5 * time.Second)
 fmt.Fprintf(conn, "Goodbye!\n")
}

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

func startServer(config Config) {
 //need to pass the port we want to host the server on



 log.Println("starting server at "+*config.IP+":"+*config.Port)
 s, err := newServer(":"+*config.Port)
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

