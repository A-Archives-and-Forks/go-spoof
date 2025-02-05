package main

import(
	"fmt"
)


func main(){
	var config = config() //collect information for setup
	startServer(config)
	fmt.Println(*config.IP)
}
