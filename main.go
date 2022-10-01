package main

import (
	"path/filepath"

	"github.com/hlandau/dexlogconfig"
	"gopkg.in/hlandau/easyconfig.v1"
	service "gopkg.in/hlandau/service.v2"

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

	service.Main(&service.Info{
		Description:   "Namecoin to AIA Daemon",
		DefaultChroot: service.EmptyChrootPath,
		NewFunc: func() (service.Runnable, error) {
			return server.New(&cfg)
		},
	})
}

// © 2014-2021 Namecoin Developers    GPLv3 or later
