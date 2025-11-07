/*
 * Auth: config.go
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
	"errors"
	"os"
	"strings"
	"time"

	"github.com/goccy/go-yaml"
	"github.com/rs/zerolog/log"
)

const DefaultSecretHostKey = "<change required, otherwise Vayen Auth can be compromised!>"

type Config struct {
	Database               DatabaseConfig
	Session                SessionConfig
	TLS                    TLSConfig
	Port                   int
	InternalHostsSecretKey string
}

type DatabaseConfig struct {
	Host     string
	Port     int
	Name     string
	Username string
	Password string
}

type SessionConfig struct {
	ValidFor           time.Duration `yaml:"validFor"`
	CacheClearInterval time.Duration `yaml:"clearSessionCache"`
	CacheSize          int64         `yaml:"sessionCacheSize"`
}

type TLSConfig struct {
	CertFile string
	KeyFile  string
}

func SaveDefaultConfig() error {
	config := Config{
		Database: DatabaseConfig{
			Host:     "localhost",
			Port:     5432,
			Name:     "<change this to your database name>",
			Username: "<change this to your database username>",
			Password: "<change this to your database password>",
		},
		Session: SessionConfig{
			ValidFor:           15 * time.Minute,
			CacheClearInterval: 10 * time.Minute,
			CacheSize:          32 * MiB,
		},
		TLS: TLSConfig{
			CertFile: "",
			KeyFile:  "",
		},
		Port:                   8080,
		InternalHostsSecretKey: DefaultSecretHostKey,
	}

	err := config.Save()
	if err != nil {
		return err
	}

	return nil
}

func (config Config) Save() error {
	marshal, err := yaml.Marshal(config)
	if err != nil {
		return err
	}

	err = os.WriteFile(ConfigFilePath, marshal, 0644)
	if err != nil {
		return err
	}

	return nil
}

func (config Config) Validate() error {
	// Normal config validation
	if config.Port == 0 {
		return errors.New("port is required")
	}
	if strings.TrimSpace(config.InternalHostsSecretKey) == "" {
		return errors.New("internal hosts secret key is required")
	}

	// Database config validation
	if strings.TrimSpace(config.Database.Host) == "" {
		return errors.New("database host is required")
	}
	if config.Database.Port == 0 {
		return errors.New("database port is required")
	}
	if strings.TrimSpace(config.Database.Name) == "" {
		return errors.New("database name is required")
	}
	if strings.TrimSpace(config.Database.Name) == "<change this to your database name>" {
		return errors.New("database name must be changed, it cannot be the default")
	}
	if strings.TrimSpace(config.Database.Username) == "" {
		return errors.New("database username is required")
	}
	if strings.TrimSpace(config.Database.Username) == "<change this to your database username>" {
		return errors.New("database username must be changed, it cannot be the default")
	}
	if strings.TrimSpace(config.Database.Password) == "" {
		log.Warn().Msg("database password is empty, we recommend using a password for security reasons!")
	}
	if strings.TrimSpace(config.Database.Password) == "<change this to your database password>" {
		return errors.New("database password must be changed, it cannot be the default")
	}

	// Session config validation
	if config.Session.ValidFor == 0 {
		return errors.New("duration length for a session validity is required")
	}
	if config.Session.CacheClearInterval == 0 {
		return errors.New("duration length for clearing the session cache is required")
	}

	// TLS config validation
	if strings.TrimSpace(config.TLS.CertFile) == "" {
		log.Warn().Msg("TLS certificate file is empty, we recommend using a certificate for security reasons so that the server can use TLS")
	}
	if strings.TrimSpace(config.TLS.KeyFile) == "" {
		log.Warn().Msg("TLS key file is empty, we recommend using a key for security reasons so that the server can use TLS")
	}

	return nil
}

func ReadConfig() (Config, error) {
	file, err := os.ReadFile(ConfigFilePath)
	if err != nil {

		return Config{}, err
	}

	var config Config
	err = yaml.Unmarshal(file, &config)
	if err != nil {
		return Config{}, err
	}

	return config, nil
}
