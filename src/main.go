/*
 * Auth: main.go
 * Copyright (C) 2025 mtctx
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the **GNU General Public License** as published
 * by the Free Software Foundation, either **version 3** of the License, or
 * (at your option) any later version.
 *
 * *This program is distributed WITHOUT ANY WARRANTY;** see the
 * GNU General Public License for more details, which you should have
 * received with this program.
 *
 * SPDX-FileCopyrightText: 2025 mtctx
 * SPDX-License-Identifier: GPL-3.0-only
 */

package src

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"src/data"
	"src/files"
	"src/route"
	"src/service"
	"strings"

	"github.com/dgraph-io/ristretto/v2"
	"github.com/jackc/pgx/v5"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

const ConfigFilePath = "./files.yml"

var ServerAddress string

func main() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	fmt.Println("Starting Vayen Auth")
	fmt.Println("Loading files...")

	// Check if the files file exists, if not, save the default files file
	if _, err := os.Stat(ConfigFilePath); os.IsNotExist(err) {
		fmt.Println("Config file not found, creating default files file...")
		err := files.SaveDefaultConfig(ConfigFilePath)
		if err != nil {
			return
		}
		os.Exit(1)
	}

	config, err := files.ReadConfig(ConfigFilePath)
	if err != nil {
		panic(err)
	}
	if config == files.DefaultConfig {
		log.Error().Msg("Config file cannot be the default files file, please edit the files file and try again!")
		os.Exit(1)
	}
	err = config.Validate()
	if err != nil {
		log.Error().Msg("Config file is invalid, please edit the files file and try again!")
		log.Err(err)
		os.Exit(1)
	}
	ServerAddress = fmt.Sprintf("localhost:%d", config.Port)

	fmt.Println("Connecting to database...")
	connection, err := pgx.Connect(context.Background(), buildDatabaseURL(config.Database))
	if err != nil {
		panic(err)
	}
	defer connection.Close(context.Background())

	fmt.Println("Creating Session Cache...")
	cache, err := ristretto.NewCache(&ristretto.Config[[]byte, data.Session]{
		NumCounters: 1e7,
		MaxCost:     1 << 30,
		BufferItems: 64,
		Metrics:     true,
	})
	if err != nil {
		panic(err)
	}
	defer cache.Close()

	fmt.Println("Registering routes...")
	mux := http.NewServeMux()
	mux.HandleFunc("POST /session/create", route.HandleSessionCreate)
	mux.HandleFunc("GET /session/valid", route.HandleSessionValid)
	mux.HandleFunc("GET /session/expired", route.HandleSessionExpired)
	mux.HandleFunc("DELETE /session/invalidate", route.HandleSessionInvalidate)

	var finalHandler http.Handler = mux
	finalHandler = route.SessionMiddleware(
		config,
		service.SessionServiceSetup{
			Database:  connection,
			DBContext: context.Background(),
			Cache:     cache,
		}, finalHandler)

	fmt.Printf("Starting server on %s ...\n", ServerAddress)
	if config.TLS.Enabled {
		if strings.TrimSpace(config.TLS.CertFile) == "" || strings.TrimSpace(config.TLS.KeyFile) == "" {
			log.Error().Msg("TLS certificate file or key file path is empty, please edit the file paths and try again!")
			os.Exit(1)
		}
		err = http.ListenAndServeTLS(ServerAddress, config.TLS.CertFile, config.TLS.KeyFile, finalHandler)
	} else {
		err = http.ListenAndServe(ServerAddress, finalHandler)
	}
	if err != nil {
		panic(err)
	}
}

func buildDatabaseURL(config files.DatabaseConfig) string {
	return fmt.Sprintf("postgres://%s:%s@%s:%d/%s", config.Username, config.Password, config.Host, config.Port, config.Name)
}
