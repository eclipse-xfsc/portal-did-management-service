package main

import (
	"os"
)

func main() {
	// Init Logger
	InitializeLogger()

	// Get config
	config, err := getConfig()
	if err != nil {
		Logger.Error(err)
		os.Exit(0)
	}

	// Start Rest API server
    startServer(&config.port)
}