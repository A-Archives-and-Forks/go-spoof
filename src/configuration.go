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
	"github.com/AnatolyRugalev/goregen"
	"regexp/syntax"
	"encoding/hex"
)

type Config struct {
    IP                   *string
    Port                 *string
    ServiceSignaturePath *string
    ConfigurationFilePath *string
    LoggingFilePath      *string
    Daemon               *string
    Verbosity            *string
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

	configuration.IP 					    = flag.String("i", addr, "ip : Bind to a particular IP address")
	configuration.Port 					= flag.String("p", "4444", "port : bind to a particular PORT number")
	configuration.ServiceSignaturePath 	= flag.String("s", "/home/jboyd/projects/go-spoof/tools/portspoof_signatures", "file_path : portspoof service signature regex. file")
	configuration.ConfigurationFilePath = flag.String("c", "default", "file_path : portspoof configuration file")
	configuration.LoggingFilePath		= flag.String("l", "default", "file_path : log port scanning alerts to a file")
	configuration.Daemon 					= flag.String("D", "default", "run as daemon process")
	configuration.Verbosity 				= flag.String("v", "default", "be verbose")
	flag.Parse()
	configuration = processSignatureFile(configuration)
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

//Processes the signature file and returns a map of port:signature
func processSignatureFile(config Config) Config {

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
	for i:=0;i <= 100; i++ {
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

		portSignatureMap[i] = output
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


