package main

import (
	"path/filepath"

	"github.com/hlandau/dexlogconfig"
	"gopkg.in/hlandau/easyconfig.v1"

	"github.com/namecoin/encaya/server"
)

func main() {
	cfg := server.Config{}

	config := easyconfig.Configurator{
		ProgramName: "encaya",
	}
	config.ParseFatal(&cfg)
	dexlogconfig.Init()

	// We use the configPath to resolve paths relative to the config file.
	cfg.ConfigDir = filepath.Dir(config.ConfigFilePath())

	server.GenerateCerts(&cfg)
}

// © 2014-2021 Namecoin Developers    GPLv3 or later
