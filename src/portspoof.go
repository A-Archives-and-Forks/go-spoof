package main

import(
	"log"
	"github.com/sevlyar/go-daemon"

)


func main(){

		cntxt := &daemon.Context{
			PidFileName: "sample.pid",
			PidFilePerm: 0644,
			LogFileName: "sample.log",
			LogFilePerm: 0640,
			WorkDir: "./", 
			Umask: 027,
			Args: []string{"[main -s ../tools/test]"},
		}

		daemon, err := cntxt.Reborn()
		if err != nil {
			log.Fatal("RIP", err)
		}
		if daemon != nil {
			log.Println("UP!")
			return
		}

	defer cntxt.Release()


	var config = config() //collect information for setup
	startServer(config)
}
