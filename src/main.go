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

	"github.com/dgraph-io/ristretto/v2"
	"github.com/jackc/pgx/v5"
	"github.com/rs/zerolog"
)

const ConfigFilePath = "./config.yml"

var ServerAddress string

func main() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	fmt.Println("Starting Vayen Auth")
	fmt.Println("Loading config...")

	// Check if config file exists, if not save the default config file
	if _, err := os.Stat(ConfigFilePath); os.IsNotExist(err) {
		fmt.Println("Config file not found, creating default config file...")
		err := SaveDefaultConfig()
		if err != nil {
			return
		}
		os.Exit(1)
	}

	config, err := ReadConfig()
	if err != nil {
		panic(err)
	}
	ServerAddress = fmt.Sprintf("localhost:%d", config.Port)

	fmt.Println("Connecting to database...")
	connection, err := pgx.Connect(context.Background(), buildDatabaseURL(config.Database))
	if err != nil {
		panic(err)
	}
	defer connection.Close(context.Background())

	fmt.Println("Creating Session Cache...")
	cache, err := ristretto.NewCache(&ristretto.Config[[]byte, Session]{
		NumCounters: 1e7,
		MaxCost:     1 << 30,
		BufferItems: 64,
		Metrics:     true,
	})
	if err != nil {
		panic(err)
	}
	defer cache.Close()

	fmt.Printf("Starting server on %s ...\n", ServerAddress)
	err = http.ListenAndServe(ServerAddress, nil)
	if err != nil {
		panic(err)
	}
}

func buildDatabaseURL(config DatabaseConfig) string {
	return fmt.Sprintf("postgres://%s:%s@%s:%d/%s", config.Username, config.Password, config.Host, config.Port, config.Name)
}
