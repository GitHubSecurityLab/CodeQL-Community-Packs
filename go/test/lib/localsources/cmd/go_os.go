package main

import (
	"fmt"
	"os"
)

func main() {
	args := os.Args
	fmt.Println(args[0], args[1])

	// Environ
	env := os.Environ()
	fmt.Println(env[0], env[1])

	// getenv
	myenv := os.Getenv("HOME")
	fmt.Println(myenv)

}
