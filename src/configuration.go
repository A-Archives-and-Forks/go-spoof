/*
GO-SPOOF 

Configuration.go processes command line arguments and collects information
for defaults arguments that have not been explicitly defined by the user. 

TO-DO
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
	"bufio"
	"math/rand"
	"time"
	"strings"
	"strconv"
	"github.com/AnatolyRugalev/goregen"
	"regexp/syntax"
	"encoding/hex"
	"os/exec"
)

type Config struct {
    IP                   *string
    Port                 *string
    ServiceSignaturePath *string
    ConfigurationFilePath *string
    LoggingFilePath      *string
    Daemon               *string
    Verbosity            *string
	SpoofPorts			 *string
	StartTables			 *string
	FlushTables			 *string
	OnStart				 *string
	Yaml				 *string
	PortSignatureMap     map[int]string
}

func config() Config{

	var configuration Config;

	//Get default IP
	addr := getIP()
	if addr == "1" {
		log.Println("Error getting default IP - try manually providing the IP")
		os.Exit(1)
	}

	//Command line flags (FLAG, DEFAULT, HELP)
	configuration.IP 					    = flag.String("i", addr, "ip : Bind to a particular IP address")
	configuration.Port 						= flag.String("p", "4444", "port : bind to a particular PORT number")
	configuration.ServiceSignaturePath 		= flag.String("s", " ", "file_path : go-spoof service signature regex. file")
	configuration.LoggingFilePath			= flag.String("l", " ", "file_path : log port scanning alerts to a file")
	configuration.Daemon 					= flag.String("D", " ", "run as daemon process")
	configuration.Verbosity 				= flag.String("v", " ", "be verbose")
	configuration.SpoofPorts                = flag.String("sP", "1-65535", "Provide a range of ports (1-10) or a list of ports 1,9,32. Default is all ports")
	configuration.StartTables				= flag.String("sT", " ", "setup iptables to route traffic to binded port")
	configuration.FlushTables				= flag.String("fT", " ", "reset iptables")
	configuration.OnStart					= flag.String("oS", " ", "start go-spoof on boot")
	configuration.Yaml						= flag.String("Y", " ", "load configuration from yaml file")
	flag.Parse()
	configuration = processArgs(configuration) //perform setup tasks specified by the user 
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

func processArgs(config Config) Config {
	//Start / stop iptables 

	//process default ports - need to take in range and comma separated list

	//figure out how to run as a daemon 

	var minPort int; 
	var maxPort int; 
	var err error;
	var intPortArray []int
	isList := false
	

	if *config.Daemon != " " {
		log.Println("Daemon")
		os.Exit(0)
	} 
	if *config.SpoofPorts != "1-65535" {
		ports := *config.SpoofPorts

		if !strings.Contains(ports, " ") { //no spaces allowed in input
			if strings.Contains(ports, ",") {
				log.Println("Comma deliminated list")
				isList = true
				portArray := strings.Split(ports, ",")

				//when user specifies a list, minPort and maxPort merely become min and max indexes to parse the array - they no longer represent the literal port numbers. 
				minPort = 0 
				maxPort = len(portArray) - 1

				//convert port numbers from strings to ints, store in new array called intPortArray
				var holder int
				for i := 0; i < len(portArray); i++ {
					holder, err = strconv.Atoi(portArray[i])
					if err != nil {
						log.Println("Error in converting string in port array to int", err)
					}

					if holder > 65535 {
						log.Println("A port in the provided list exceeds the port maximum of 65535")
						os.Exit(1)
					}

					intPortArray = append(intPortArray, holder)
				}



			} else if strings.Contains(ports, "-") {
				log.Println("Range")
				portRange := strings.Split(ports, "-")

				maxPort, err = strconv.Atoi(portRange[1])
				if err != nil {
					log.Println("maxPort cast to int error", err)
					os.Exit(1)
				}
				minPort, err = strconv.Atoi(portRange[0])
				if err != nil {
					log.Println("minPort cast to int error", err)
				}
				log.Println(maxPort, minPort)

				//If user provides bad arguments (e.g. 1-100-200, 1-999999, 999-1)
				if len(portRange) > 2 {
					log.Println("Invalid range. Include only TWO numbers: LOW-HIGH")
					os.Exit(1)
				}
				if maxPort > 65535 {
					log.Println("Upper range too high! There are only 65535 Ports!")
					os.Exit(1)
				}
				if minPort > maxPort {
					log.Println("Lower range should be lower than upper range!")
					os.Exit(1)
				}
			} else if !strings.Contains(ports, "-") && !strings.Contains(ports, ",") {
				maxPort, _ = strconv.Atoi(ports) 
				minPort, _ = strconv.Atoi(ports)
				//THIS DOES NOT WORK - NEED TO ADD A CASE FOR A SINGLE PORT IN THE PROCESS SIG FILE FUNCTION 
			}
		} else {
			log.Println("Do not include spaces in port range/list")
			os.Exit(0)
		}
	} 

	if *config.StartTables != " " {
		log.Println("Start IPTABLES on user provided port")
		//two versions of port - one casted to an integer for sanitization - another kept as a string for exec.Command()
		intPort, err := strconv.Atoi(*config.StartTables) 
		if err != nil {
			log.Println("Error in converting port string input to int.", err)
			os.Exit(1)
		}
		port := *config.StartTables

		if intPort > 65535 || intPort < 0 {
			log.Println("Invalid port number - port must be between 0 and 65535")
			os.Exit(1)
		}

		log.Println(net.Interfaces())

		cmd := exec.Command("iptables", "-t", "nat", "-A", "PREROUTING", "-i", "eth0", "-p", "tcp", "-m", "tcp", "--dport", "1:65535", "-j", "REDIRECT", "--to-ports", port)
		stdout, err := cmd.Output()
		if err != nil {
			log.Println("iptables command failed", err)
			os.Exit(1)
		} else {
			log.Println(stdout)
		}
	} 
	if *config.FlushTables == "Y" || *config.FlushTables == "y" {
		log.Println("Flush IPTABLES on user provided port")

		cmd := exec.Command("iptables", "-t", "nat", "-F")

		os.Exit(0)
	} 
	if *config.OnStart == "Y" {
		log.Println("Start go-spoof on boot")
		os.Exit(0)
	} 

	config = processSignatureFile(config, minPort, maxPort, intPortArray, isList) //read signatures from configuration file
	return config

}

//Processes the signature file and returns a map of port:signature
func processSignatureFile(config Config, minPort int, maxPort int, intPortArray []int, isList bool) Config {

	var signatureLines []string;
	portSignatureMap := make(map[int]string)

	file, err := os.Open(*config.ServiceSignaturePath)
	if err != nil {
		log.Fatal("Error on opening signatures file", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	
	for scanner.Scan() {
		signatureLines = append(signatureLines, scanner.Text())
	}



	rand.Seed(time.Now().UnixNano())
	//re := regexp.MustCompile(`\\x[0-9a-fA-F]{2}`)
	//re2 := regexp.MustCompile(`\0`)
	var signatureLine string


	for i:=minPort;i <= maxPort; i++ {
		signatureLine = signatureLines[rand.Intn(len(signatureLines))]

		generator, err := regen.NewGenerator(signatureLine, &regen.GeneratorArgs{Flags: syntax.PerlX, MaxUnboundedRepeatCount: 3})
		if err != nil {
			log.Println("Critical Error", err)
			os.Exit(1)
		}
		output := generator.Generate()

		
		//process hex values
		//output = re.ReplaceAllStringFunc(signatureLine, replaceHex)
		//output = re2.ReplaceAllStringFunc(signatureLine, \0)

		if isList == false {
			portSignatureMap[i] = output
		} else {
			portSignatureMap[intPortArray[i]] = output
		}
	}
	config.PortSignatureMap = portSignatureMap

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
	log.Println(portSignatureMap)
	return config
}

func replaceHex(match string) string {
	hexValue := match[2:]
	bytes, err := hex.DecodeString(hexValue)
	if err != nil {
		log.Println("Error decoding hex string: ", err)
		return match
	}
	return string(bytes)
}


