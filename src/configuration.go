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
	"bufio"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp/syntax"
	"strconv"
	"strings"
	"sync"
	"time"

	regen "github.com/AnatolyRugalev/goregen"
)

type Config struct {
	IP                    *string
	Port                  *string
	ServiceSignaturePath  *string
	ConfigurationFilePath *string
	LoggingFilePath       *string
	Daemon                *string
	Verbosity             *string
	SpoofPorts            *string
	StartTables           *string
	TablesRange           *string
	FlushTables           *string
	OnStart               *string
	Yaml                  *string
	SleepOpt              *string
	PortSignatureMap      map[int]string
	HoneypotMode          *string
	ThrottleLevel         *string
	RubberGlueMode        *string
	ExcludedPorts         *string
	BootFlag              *bool
	RemoveBoot            *bool
}

func config() Config {

	var configuration Config

	//Get default IP
	addr := getIP()
	if addr == "1" {
		log.Fatal("Error getting default IP - try manually providing the IP")

	}

	//Command line flags (FLAG, DEFAULT, HELP)
	configuration.IP = flag.String("i", addr, "ip : Bind to a particular IP address")
	configuration.Port = flag.String("p", "4444", "port : bind to a particular PORT number")
	configuration.ServiceSignaturePath = flag.String("s", "../tools/portspoof_signatures", "file_path : go-spoof service signature regex. file")
	configuration.LoggingFilePath = flag.String("l", " ", "file_path : log port scanning alerts to a file")
	configuration.Daemon = flag.String("D", " ", "run as daemon process")
	configuration.SpoofPorts = flag.String("sP", "1-65535", "Provide a range of ports (1-10) or a list of ports 1,9,32, or a single port")
	configuration.StartTables = flag.String("sT", " ", "setup iptables to bind to a single port (bind to this port using -p). Specify specific range of ports to redirect FROM with -r")
	configuration.TablesRange = flag.String("r", "1:65535", "port range for iptables to redirect from. Format is (low port):(high port) Must be used with -sT arg")
	configuration.FlushTables = flag.String("fT", " ", "reset iptables")
	configuration.Yaml = flag.String("Y", " ", "load configuration from yaml file")
	configuration.SleepOpt = flag.String("w", "0", "provide a number of seconds to slow down service scan per port")
	configuration.HoneypotMode = flag.String("honey", "N", "Enable honeypot mode to log the attackers info (Y/N)")
	configuration.ThrottleLevel = flag.String("t", "0", "throttle delay level (1 to 5): delays 5, 10, 30, 40, 80 minutes")
	configuration.RubberGlueMode = flag.String("rg", "N", "Enable Rubber Glue mode with -rg y. Overrides all other flags")
	configuration.ExcludedPorts = flag.String("e", "", "Excludes ports that are specified")
	configuration.BootFlag = flag.Bool("boot", false, "Set up go-spoof to persist at boot via systemd")
	configuration.RemoveBoot = flag.Bool("rm", false, "Removes and presets saved with --boot to start new")
	flag.Parse()
	return configuration
}

func getIP() string {
	addr, err := net.InterfaceAddrs()
	if err != nil {
		log.Fatal(err)
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
	//rubber glue implimentation
	if *config.RubberGlueMode == "Y" || *config.RubberGlueMode == "y" {
		if *config.Port != "4444" || *config.SpoofPorts != "1-65535" || *config.HoneypotMode == "Y" || *config.ThrottleLevel != "0" {
			log.Fatal("Rubber Glue mode (-rg) must be used alone. Do not include other flags like -p, -sP, -honey, or -t.")
		}
		log.Println("Rubber Glue mode active. Listening and capturing...")
		return config
		//whole block forces exclusivity
	}

	minPort := 1
	maxPort := 65535
	var err error
	var intPortArray []int
	isList := false

	if *config.BootFlag {
		args := []string{}
		for _, arg := range os.Args[1:] {
			if arg != "--boot" {
				args = append(args, arg)
			}
		}

		user := os.Getenv("SUDO_USER")
		if user == "" {
			user = os.Getenv("USER")
		}

		execPath, err := filepath.EvalSymlinks("/proc/self/exe") //added to see if this fixes the script
		if err != nil {
			log.Fatalf("[-] Failed to get executable path: %v", err)
		}
		// Convert signature file path (-s) to absolute if it's relative
		for i, arg := range args {
			if i > 0 && args[i-1] == "-s" && !filepath.IsAbs(arg) {
				absSigPath, err := filepath.Abs(arg)
				if err != nil {
					log.Fatalf("[-] Failed to resolve absolute path for signature file: %v", err)
				}
				if _, err := os.Stat(absSigPath); os.IsNotExist(err) {
					log.Fatalf("[-] Signature file does not exist: %s", absSigPath)
				}
				args[i] = absSigPath
			}
		}
		fullCmd := execPath + " " + strings.Join(args, " ")
		serviceName := "gospoof.service"

		user = os.Getenv("SUDO_USER")
		if user == "" {
			user = os.Getenv("USER")
		}
		unit := fmt.Sprintf(`[Unit]
        Description=GoSpoof Startup Service
        After=network.target

        [Service]
		ExecStartPre=/bin/bash -c "/usr/sbin/iptables -t nat -C PREROUTING -p tcp -m tcp --dport 1:65535 -j REDIRECT --to-ports 4444 || /usr/sbin/iptables -t nat -A PREROUTING -p tcp -m tcp --dport 1:65535 -j REDIRECT --to-ports 4444"		ExecStart=%s 
		WorkingDirectory=/home/kali/GoSpoof/src
        Restart=always
        User=root
		Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

        [Install]
        WantedBy=multi-user.target
        `, fullCmd)

		if os.Geteuid() != 0 {
			log.Fatalln("[-] Must run as root to write systemd service file.")
		}

		err = os.WriteFile("/etc/systemd/system/"+serviceName, []byte(unit), 0644)
		if err != nil {
			log.Fatalf("[-] Failed to write systemd service file: %v", err)
		}

		exec.Command("systemctl", "daemon-reexec").Run()
		exec.Command("systemctl", "daemon-reload").Run()
		exec.Command("systemctl", "enable", serviceName).Run()

		log.Println("[+] Systemd service created and enabled.")
	}
	if *config.RemoveBoot {
		serviceName := "gospoof.service"
		unitPath := "/etc/systemd/system/" + serviceName

		log.Println("[*] Removing GoSpoof systemd boot persistence...")

		// stoppes and disables service
		exec.Command("systemctl", "stop", serviceName).Run()
		exec.Command("systemctl", "disable", serviceName).Run()

		// delete the service file
		if _, err := os.Stat(unitPath); err == nil {
			err := os.Remove(unitPath)
			if err != nil {
				log.Printf("[-] Failed to remove systemd service file: %v", err)
			} else {
				log.Println("[+] Deleted:", unitPath)
			}
		} else {
			log.Println("[*] Service file not found. Nothing to delete.")
		}

		// sys clean up
		exec.Command("systemctl", "daemon-reexec").Run()
		exec.Command("systemctl", "daemon-reload").Run()

		log.Println("[+] GoSpoof will no longer run at boot.")
		os.Exit(0)
	}

	if *config.ThrottleLevel != "0" {
		level, err := strconv.Atoi(*config.ThrottleLevel)
		if err != nil || level < 1 || level > 5 {
			log.Fatal("Invalid throttle level for -t. Use -t1 to -t5.")
		}
		delayMinutes := 5 * (1 << (level - 1))

		// convert it to a string that looks like a number of minutes, stored in config.SleepOpt
		*config.SleepOpt = strconv.Itoa(delayMinutes * 60)
	}

	if *config.SpoofPorts != "1-65535" {
		ports := *config.SpoofPorts

		if !strings.Contains(ports, " ") { //no spaces allowed in input
			if strings.Contains(ports, ",") {
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
						log.Fatal("Error in converting string in port array to int", err)
					}

					if holder > 65535 {
						log.Fatal("A port in the provided list exceeds the port maximum of 65535")

					}

					intPortArray = append(intPortArray, holder)
				}

			} else if strings.Contains(ports, "-") {
				portRange := strings.Split(ports, "-")

				maxPort, err = strconv.Atoi(portRange[1])
				if err != nil {
					log.Fatal("maxPort cast to int error", err)

				}
				minPort, err = strconv.Atoi(portRange[0])
				if err != nil {
					log.Fatal("minPort cast to int error", err)
				}

				//If user provides bad arguments (e.g. 1-100-200, 1-999999, 999-1)
				if len(portRange) > 2 {
					log.Fatal("Invalid range. Include only TWO numbers: LOW-HIGH")

				}
				if maxPort > 65535 || maxPort < 0 || minPort > 65535 || minPort < 0 {
					log.Fatal("Invalid port number in -sP - port range must be between 0 and 65535")

				}
				if minPort > maxPort {
					log.Fatal("Lower range should be lower than upper range!")

				}
			} else if !strings.Contains(ports, "-") && !strings.Contains(ports, ",") {
				maxPort, _ = strconv.Atoi(ports)
				minPort, _ = strconv.Atoi(ports)
				//THIS DOES NOT WORK - NEED TO ADD A CASE FOR A SINGLE PORT IN THE PROCESS SIG FILE FUNCTION
			}
		} else {
			log.Println("Do not include spaces in port range/list")

		}
	}
	if *config.StartTables != " " {
		//two versions of port - one casted to an integer for sanitization - another kept as a string for exec.Command()

		if *config.TablesRange != "1:65535" { //if custom range specified with -r, sanitize - exit if goofy input
			iptablesRange := *config.TablesRange
			var rangeArray []string
			if strings.Contains(iptablesRange, ":") {
				rangeArray = strings.Split(iptablesRange, ":")
			} else {
				log.Fatal("Format for -r - <LOW PORT>:<HIGH PORT> - invalid input")

			}

			upperRange, err := strconv.Atoi(rangeArray[1])
			if err != nil {
				log.Fatal("Error in string to int conversion ", err)

			}
			lowerRange, err := strconv.Atoi(rangeArray[0])
			if err != nil {
				log.Fatal("Error in string to int conversion", err)

			}

			if upperRange < lowerRange {
				log.Fatal("Upper range must be greater than or equal to lower range")

			}
			if upperRange > 65535 || upperRange < 0 || lowerRange > 65535 || lowerRange < 0 {
				log.Fatal("Invalid port number in -r - port range must be between 0 and 65535")
			}
		}

		intPort, err := strconv.Atoi(*config.StartTables)
		if err != nil {
			log.Fatal("Error in converting port string input to int.", err)

		}
		port := *config.StartTables

		if intPort > 65535 || intPort < 0 {
			log.Fatal("Invalid port number in -sT - port must be between 0 and 65535")

		}

		cmd := exec.Command("iptables", "-t", "nat", "-A", "PREROUTING", "-p", "tcp", "-m", "tcp", "--dport", *config.TablesRange, "-j", "REDIRECT", "--to-ports", port) //should add argument for actual interface
		_, err = cmd.Output()
		if err != nil {
			log.Println("iptables command failed", err)
			log.Fatal("Note: -sT arg requires ROOT privs!")

		} else {
			log.Println("iptables command routing traffic to port ", port)
			os.Exit(0)
		}
	}
	if *config.FlushTables == "Y" || *config.FlushTables == "y" {
		cmd := exec.Command("iptables", "-t", "nat", "-F")
		_, err := cmd.Output()
		if err != nil {
			log.Println("Flush iptables failed", err)
			log.Fatal("Are you running the -fT arg with root privs?")

		} else {
			log.Println("Flushed successfully - exiting")
			os.Exit(0)
		}
	}
	if *config.SleepOpt != "0" {
		_, err := strconv.Atoi(*config.SleepOpt)
		if err != nil {
			log.Fatal("Invalid option for -w. Please input a number")
		}
	}
	log.Println("Creating Signature Port Map - Allow up to 10 seconds for larger ranges!")
	if maxPort > 10000 && isList == false {
		chunkSize := 5000
		//chunkChannel := make(chan map[int]string, (maxPort+chunkSize-1)/chunkSize) //map of maps
		chunks := make([]map[int]string, (maxPort+chunkSize-1)/chunkSize) //map of maps

		for i := range chunks {
			chunks[i] = make(map[int]string) //assign a int to string map for each 10000 chunk
		}

		var wg sync.WaitGroup
		var startIndex int
		var endIndex int

		for i := range chunks {
			wg.Add(1)

			if i == 0 {
				startIndex = 1 + i   // 1
				endIndex = chunkSize // 10000
			} else {
				startIndex = i * chunkSize        //X0000
				endIndex = startIndex + chunkSize //(X + C)0000
				startIndex = startIndex + 1       //(X0001)
			}

			if maxPort < endIndex {
				endIndex = maxPort
			}

			go func(i int, config Config, startIndex int, endIndex int, intPortArray []int, isList bool) {
				defer wg.Done()
				signatureMap := processSignatureFile(config, startIndex, endIndex, intPortArray, isList)
				chunks[i] = signatureMap

			}(i, config, startIndex, endIndex, intPortArray, isList)
		}
		wg.Wait()
		finalMap := make(map[int]string, maxPort)
		for _, chunk := range chunks {
			for k, v := range chunk {
				finalMap[k] = v
			}
		}
		config.PortSignatureMap = finalMap
		return config
	} else {
		config.PortSignatureMap = processSignatureFile(config, minPort, maxPort, intPortArray, isList)
	}

	//config = processSignatureFile(config, minPort, maxPort, intPortArray, isList) //read signatures from configuration file
	return config
}

// Processes the signature file and returns a map of port:signature
func processSignatureFile(config Config, minPort int, maxPort int, intPortArray []int, isList bool) map[int]string {

	var signatureLines []string
	portSignatureMap := make(map[int]string, maxPort)

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
	var signatureLine string

	for i := minPort; i <= maxPort; i++ {
		signatureLine = signatureLines[rand.Intn(len(signatureLines))]
		generator, err := regen.NewGenerator(signatureLine, &regen.GeneratorArgs{Flags: syntax.PerlX, MaxUnboundedRepeatCount: 3})
		if err != nil {
			log.Fatal("Critical Error", err)
		}
		output := generator.Generate()

		if isList == false {
			portSignatureMap[i] = output
		} else {
			portSignatureMap[intPortArray[i]] = output
		}
	}
	//config.PortSignatureMap = portSignatureMap

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
	return portSignatureMap
}
