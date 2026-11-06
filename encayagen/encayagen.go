package main

import (
	"path/filepath"

	_ "github.com/hlandau/buildinfo" // registers -version (xlog used to pull it in)
	"github.com/namecoin/encaya/config"
	"github.com/namecoin/encaya/logconfig"
	"github.com/namecoin/encaya/server"
)

func main() {
	cfg := server.Config{}
	logCfg := logconfig.Config{}

	loader := config.New("encaya")
	if err := loader.Register("encaya", &cfg); err != nil {
		panic(err)
	}

	if err := loader.Register("xlog", &logCfg); err != nil {
		panic(err)
	}

	loader.ParseFatal()
	logconfig.Init(&logCfg)

	// We use the configPath to resolve paths relative to the config file.
	cfg.ConfigDir = filepath.Dir(loader.ConfigFilePath())

	server.GenerateCerts(&cfg)
}

// © 2014-2021 Namecoin Developers    GPLv3 or later
