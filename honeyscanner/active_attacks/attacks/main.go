package main

import (
	"fmt"
	"strings"

	"attacks/dos"
	"attacks/piping"
	"attacks/structs"
)

func main() {
	pipe, err := piping.OpenPipe()
	if err != nil {
		fmt.Println("[-] Attacks could not start")
		return
	}
	defer pipe.Close()
	var results *structs.Results
	data, err := piping.ReadData(pipe)
	if err != nil {
		panic(err)
	}
	if data.Attack == "dos" {
		results = dos.RunDOS(data)
	}
	if results.Success {
		fmt.Printf("[+] %s Attack Finished. System is down\n", strings.ToUpper(data.Attack))
	} else {
		fmt.Printf("[-] %s Attack Finished. System is up\n", strings.ToUpper(data.Attack))
	}
	err = piping.WriteData(pipe, results)
	if err != nil {
		fmt.Println("[-] Error writing results to pipe: ", err)
		panic(err)
	}
}
