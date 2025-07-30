/*
GO-SPOOF

portspoof.go is the MAIN file of the system. 
	1. Parses command line arguments using the config() function in Configuration.go
	2. If -D == Y/y, run the program as a daemon 
	3. process remaining arguments after daemonizing / not daemonizing
	4. start the server! 

*/

package main

import(
	"log"
	"github.com/sevlyar/go-daemon"
	
)


func main(){

	var config = config() //collect information for setup

	if *config.Daemon == "Y" || *config.Daemon == "y" {
			cntxt := &daemon.Context{
				PidFileName: "sample.pid",
				PidFilePerm: 0644,
				LogFileName: "sample.log",
				LogFilePerm: 0640,
				WorkDir: "./", 
				Umask: 027,
				Args: []string{"goSpoof", "-i", *config.IP, "-p", *config.Port, "-s", *config.ServiceSignaturePath, "-l", *config.LoggingFilePath, "-sP", *config.SpoofPorts, "-sT", *config.StartTables, "-r", *config.TablesRange, "-fT", *config.FlushTables, "-Y", *config.Yaml},  
			}

			daemon, err := cntxt.Reborn()
			if err != nil {
				log.Fatal("RIP", err)
			}
			if daemon != nil {
				log.Println("Running as Daemon - allow up to 10 seconds to fully initialize")
				return
			}

		defer cntxt.Release()
	}
	
	config = processArgs(config) //perform setup tasks specified by the user 
	startServer(config)
}
