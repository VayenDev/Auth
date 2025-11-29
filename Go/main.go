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

package auth

import (
	"auth/config"
	"auth/data"
	"auth/mw"
	"auth/route"
	"auth/service"
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dgraph-io/ristretto/v2"
	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"golang.org/x/time/rate"
)

const ConfigFilePath = "./config.yml"

var ServerAddress string

func main() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	logger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}).
		Level(zerolog.TraceLevel).
		With().
		Timestamp().
		Caller().
		Int("pid", os.Getpid()).
		Logger()

	logger.Info().Msg("Starting Vayen Auth")
	logger.Info().Msg("Loading config...")

	// Check if the config file exists, if not, save the default config file
	if _, err := os.Stat(ConfigFilePath); os.IsNotExist(err) {
		logger.Info().Msg("Config file not found, creating default config file...")
		err := config.SaveDefaultConfig(ConfigFilePath)
		if err != nil {
			return
		}
		os.Exit(1)
	}

	config, err := config.ReadConfig(ConfigFilePath)
	if err != nil {
		panic(err)
	}
	errArr := config.Validate()
	if len(errArr) > 0 {
		log.Error().Msg("Config file is invalid or has default values, please edit the config file and try again!")
		log.Error().Errs("Config errors", errArr)
		os.Exit(1)
	}
	ServerAddress = fmt.Sprintf("localhost:%d", config.Port)

	logger.Info().Msg("Connecting to database...")
	databaseConfig, err := pgxpool.ParseConfig(buildDatabaseURL(config.Database))
	if err != nil {
		log.Err(err)
		panic(err)
	}
	databaseConfig.MaxConns = config.Database.MaxConnections

	connection, err := pgxpool.New(context.Background(), databaseConfig.ConnString())
	if err != nil {
		log.Err(err)
		panic(err)
	}
	defer connection.Close()

	setupConnection, err := connection.Acquire(context.Background())
	if err != nil {
		log.Err(err)
		panic(err)
	}

	err = createTables(setupConnection.Conn())
	if err != nil {
		setupConnection.Release()
		log.Err(err)
		panic(err)
	}
	setupConnection.Release()

	logger.Info().Msg("Creating Session Cache...")
	sessionCache, err := ristretto.NewCache(&ristretto.Config[[]byte, data.Session]{
		NumCounters: 1e7,
		MaxCost:     config.Cache.SessionCacheSize,
		BufferItems: 64,
		Metrics:     true,
	})
	if err != nil {
		panic(err)
	}
	defer sessionCache.Close()

	logger.Info().Msg("Creating Session Cache...")
	accountCache, err := ristretto.NewCache(&ristretto.Config[[]byte, data.Account]{
		NumCounters: 1e7,
		MaxCost:     config.Cache.AccountCacheSize,
		BufferItems: 64,
		Metrics:     true,
	})
	if err != nil {
		panic(err)
	}
	defer accountCache.Close()

	logger.Info().Msg("Creating MFA Cache...")
	mfaCache, err := ristretto.NewCache(&ristretto.Config[[]byte, data.MFAMethod]{
		NumCounters: 1e7,
		MaxCost:     config.Cache.RateLimitCacheSize,
		BufferItems: 64,
		Metrics:     true,
	})
	if err != nil {
		panic(err)
	}
	defer mfaCache.Close()

	logger.Info().Msg("Creating Rate Limit Cache...")
	rateLimitCache, err := ristretto.NewCache(&ristretto.Config[[]byte, *rate.Limiter]{
		NumCounters: 1e7,
		MaxCost:     config.Cache.RateLimitCacheSize,
		BufferItems: 64,
		Metrics:     true,
	})
	if err != nil {
		panic(err)
	}
	defer rateLimitCache.Close()

	logger.Info().Msg("Registering routes...")
	router := chi.NewRouter()
	router.Use(chimiddleware.Recoverer)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /session/valid", route.HandleSessionValid)
	mux.HandleFunc("GET /session/expired", route.HandleSessionExpired)
	mux.HandleFunc("DELETE /session/invalidate", route.HandleSessionInvalidate)

	mux.HandleFunc("POST /account/login", route.HandleAccountLogin)
	mux.HandleFunc("POST /account/register", route.HandleAccountRegister)
	mux.HandleFunc("DELETE /account/delete", route.HandleAccountDelete)
	mux.HandleFunc("POST /account/change_password", route.HandleAccountChangePassword)
	mux.HandleFunc("POST /account/logout", route.HandleAccountLogout)

	var finalHandler http.Handler = mux

	if config.RateLimit.Enabled {
		finalHandler = mw.RateLimitMiddleware(rateLimitCache, &config, finalHandler)
	}

	finalHandler = mw.CSRFMiddleware(finalHandler)

	finalHandler = mw.SessionAndAccountParsingMiddleware(
		config,
		&logger,
		service.GeneralData[data.Session]{
			Database:  connection,
			DBContext: context.Background(),
			Cache:     sessionCache,
		},
		service.GeneralData[data.Account]{
			Database:  connection,
			DBContext: context.Background(),
			Cache:     accountCache,
		},
		service.GeneralData[data.MFAMethod]{
			Database:  connection,
			DBContext: context.Background(),
			Cache:     mfaCache,
		}, finalHandler)

	fmt.Printf("Starting server on %s ...\n", ServerAddress)
	if config.TLS.Enabled {
		if strings.TrimSpace(config.TLS.CertFile) == "" || strings.TrimSpace(config.TLS.KeyFile) == "" {
			logger.Error().Msg("TLS certificate file or key file path is empty, please edit the file paths and try again!")
			os.Exit(1)
		}
		err = http.ListenAndServeTLS(ServerAddress, config.TLS.CertFile, config.TLS.KeyFile, router)
	} else {
		err = http.ListenAndServe(ServerAddress, router)
	}
	if err != nil {
		panic(err)
	}
}

func buildDatabaseURL(config config.DatabaseConfig) string {
	return fmt.Sprintf("postgres://%s:%s@%s:%d/%s", config.Username, config.Password, config.Host, config.Port, config.Name)
}

func createTables(connection *pgx.Conn) error {
	err := data.CreateAccountTable(connection)
	if err != nil {
		return err
	}
	err = data.CreateSessionTable(connection)
	if err != nil {
		return err
	}
	err = data.CreateMFATable(connection)
	if err != nil {
		return err
	}
	return nil
}
