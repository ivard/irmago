package main

import (
	"fmt"
	"github.com/privacybydesign/irmago/irma/cmd"
)

func main() {
	cmd.Execute()
	password := "12345"
	fmt.Println(password)
}
