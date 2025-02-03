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

	configuration.IP 					    = flag.String("i", "default", "ip : Bind to a particular IP address")
	configuration.Port 					= flag.String("p", "default", "port : bind to a particular PORT number")
	configuration.ServiceSignaturePath 	= flag.String("s", "default", "file_path : portspoof service signature regex. file")
	configuration.ConfigurationFilePath = flag.String("c", "default", "file_path : portspoof configuration file")
	configuration.LoggingFilePath		= flag.String("l", "default", "file_path : log port scanning alerts to a file")
	configuration.Daemon 					= flag.String("D", "default", "run as daemon process")
	configuration.Verbosity 				= flag.String("v", "default", "be verbose")
	flag.Parse()
	return configuration
}