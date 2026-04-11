package main

import (
	"os"

	"github.com/sud0x0/bsau/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
