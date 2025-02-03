/*
GO-SPOOF 

Configuration.go processes command line arguments and collects information
for defaults arguments that have not been explicitly defined by the user. 

TO-DO
	- ADD DEFAULT IP (current interface)
	- ADD DEFAULT PORT (4444)
	- ADD DEFAULT FILE CONFIG PATH
	- ADD DEFAULT SERVICE SIGNATURE FILE PATH
	- NO DEFAULT LOGGING PATH IS NEEDED - OFF BY DEFAULT
*/

package main


import (
	"flag"
	"net"
	"log"
	"os"
)

type Config struct {
    IP                   *string
    Port                 *string
    ServiceSignaturePath *string
    ConfigurationFilePath *string
    LoggingFilePath      *string
    Daemon               *string
    Verbosity            *string
}

func config() Config{

	var configuration Config;

	//Get default IP
	addr := getIP()
	if addr == "1" {
		log.Println("Error getting default IP - try manually providing the IP")
		os.Exit(1)
	}

	configuration.IP 					    = flag.String("i", addr, "ip : Bind to a particular IP address")
	configuration.Port 					= flag.String("p", "4444", "port : bind to a particular PORT number")
	configuration.ServiceSignaturePath 	= flag.String("s", "default", "file_path : portspoof service signature regex. file")
	configuration.ConfigurationFilePath = flag.String("c", "default", "file_path : portspoof configuration file")
	configuration.LoggingFilePath		= flag.String("l", "default", "file_path : log port scanning alerts to a file")
	configuration.Daemon 					= flag.String("D", "default", "run as daemon process")
	configuration.Verbosity 				= flag.String("v", "default", "be verbose")
	flag.Parse()
	return configuration
}

func getIP() string {
	addr, err := net.InterfaceAddrs()
	if err != nil {
		log.Println(err)
		return "1"
	}


	for _, addr := range addr {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil || ipnet.IP.To16 != nil {
				return ipnet.IP.String()
			}
		}
	}
	return "1"
}