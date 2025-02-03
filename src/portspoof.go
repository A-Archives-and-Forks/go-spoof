package main

import(
	"fmt"
)


func main(){
	var config = config()
	fmt.Println(*config.IP)
}
