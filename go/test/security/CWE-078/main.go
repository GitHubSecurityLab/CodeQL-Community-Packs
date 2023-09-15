package main

import (
	"fmt"
	"net/http"
	"os/exec"
)

// func handler is unused (U1000)go-staticcheck
func handler(req *http.Request) {
	cmdName := req.URL.Query()["cmd"][0]
	cmd := exec.Command(cmdName)
	cmd.Run()
}

func usedHandler(w http.ResponseWriter, req *http.Request) {

	fmt.Fprintf(w, "Welcome!!!")

	cmds, ok := req.URL.Query()["cmd"]
	if !ok || len(cmds) < 1 {
		http.Error(w, "Missing cmd parameter", http.StatusBadRequest)
		return
	}

	cmdName := cmds[0]
	cmd := exec.Command(cmdName)
	err := cmd.Run()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "Command '%s' executed successfully!", cmdName)
}

func justAFunction() {
	println("I'm just a function")
}

func main() {
	justAFunction()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Welcome to my website!")
	})

	http.HandleFunc("/execute", usedHandler)

	http.ListenAndServe(":8080", nil)
}