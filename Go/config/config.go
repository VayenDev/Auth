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

package config

import (
	"auth/other"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/goccy/go-yaml"
	"github.com/rs/zerolog/log"
)

type Config struct {
	Database  DatabaseConfig
	Session   SessionConfig
	TLS       TLSConfig
	RateLimit RateLimitConfig
	Cache     CacheConfig
	MFA       MFAConfig
	Port      int
}

type DatabaseConfig struct {
	Host           string
	Port           int
	Name           string
	Username       string
	Password       string
	MaxConnections int32
}

type SessionConfig struct {
	ValidFor time.Duration `yaml:"validFor"`
}

type TLSConfig struct {
	Enabled  bool
	CertFile string
	KeyFile  string
}

type RateLimitConfig struct {
	Enabled     bool
	Window      time.Duration
	MaxRequests int
}

type CacheConfig struct {
	SessionCacheSize   int64
	AccountCacheSize   int64
	RateLimitCacheSize int64
}

type MFAConfig struct {
	TOTP     TOTPConfig
	WebAuthn WebAuthnConfig
}

type TOTPConfig struct {
	Issuer      string
	ImageWidth  int
	ImageHeight int
}
type WebAuthnConfig struct {
	RelyingPartyDisplayName string
	RelyingPartyID          string
	RelyingPartyOrigins     []string
}

var DefaultConfig = Config{
	Database: DatabaseConfig{
		Host:     "localhost",
		Port:     5432,
		Name:     "<change this to your database name>",
		Username: "<change this to your database username>",
		Password: "<change this to your database password>",
	},
	Session: SessionConfig{
		ValidFor: 15 * time.Minute,
	},
	TLS: TLSConfig{
		Enabled:  false,
		CertFile: "",
		KeyFile:  "",
	},
	RateLimit: RateLimitConfig{
		Enabled:     true,
		Window:      5 * time.Second,
		MaxRequests: 10,
	},
	Cache: CacheConfig{
		SessionCacheSize:   100 * other.MiB,
		AccountCacheSize:   20 * other.MiB,
		RateLimitCacheSize: 50 * other.MiB,
	},
	MFA: MFAConfig{
		TOTP: TOTPConfig{
			Issuer:      "Vayen Auth",
			ImageWidth:  200,
			ImageHeight: 200,
		},
		WebAuthn: WebAuthnConfig{
			RelyingPartyDisplayName: "Vayen Auth",
			RelyingPartyID:          "vayen.dev/auth",
			RelyingPartyOrigins:     []string{"https://vayen.dev/auth"},
		},
	},
	Port: 8080,
}

func SaveDefaultConfig(configFilePath string) error {
	err := DefaultConfig.Save(configFilePath)
	if err != nil {
		return err
	}

	return nil
}

func (config Config) Save(configFilePath string) error {
	marshal, err := yaml.Marshal(config)
	if err != nil {
		return err
	}

	err = os.WriteFile(configFilePath, marshal, 0644)
	if err != nil {
		return err
	}

	return nil
}

func (config Config) Validate() []error {
	errorList := make([]error, 0)

	// General Config validation
	if config.Port == 0 {
		errorList = append(errorList, errors.New("port is required"))
	}

	// Database Config validation
	if strings.TrimSpace(config.Database.Host) == "" {
		errorList = append(errorList, errors.New("database host is required"))
	}
	if config.Database.Port == 0 {
		errorList = append(errorList, errors.New("database port is required"))
	}
	if strings.TrimSpace(config.Database.Name) == "" {
		errorList = append(errorList, errors.New("database name is required"))
	}
	if strings.TrimSpace(config.Database.Name) == "<change this to your database name>" {
		errorList = append(errorList, errors.New("database name must be changed, it cannot be the default"))
	}
	if strings.TrimSpace(config.Database.Username) == "" {
		errorList = append(errorList, errors.New("database username is required"))
	}
	if strings.TrimSpace(config.Database.Username) == "<change this to your database username>" {
		errorList = append(errorList, errors.New("database username must be changed, it cannot be the default"))
	}
	if strings.TrimSpace(config.Database.Password) == "" {
		log.Warn().Msg("database password is empty, we recommend using a password for security reasons!")
	}
	if strings.TrimSpace(config.Database.Password) == "<change this to your database password>" {
		errorList = append(errorList, errors.New("database password must be changed, it cannot be the default"))
	}

	// Session Config validation
	if config.Session.ValidFor == 0 {
		errorList = append(errorList, errors.New("duration length for a session validity is required"))
	}

	// TLS Config validation
	if !config.TLS.Enabled {
		log.Warn().Msg("TLS is disabled, we recommend using TLS for security reasons")
	}
	if strings.TrimSpace(config.TLS.CertFile) == "" {
		log.Warn().Msg("TLS certificate file is empty, we recommend using a certificate for security reasons so that the server can use TLS")
	}
	if strings.TrimSpace(config.TLS.KeyFile) == "" {
		log.Warn().Msg("TLS key file is empty, we recommend using a key for security reasons so that the server can use TLS")
	}

	// Cache Config validation
	if config.Cache.SessionCacheSize == 0 {
		errorList = append(errorList, errors.New("session cache size is required"))
	}
	if config.Cache.AccountCacheSize == 0 {
		errorList = append(errorList, errors.New("account cache size is required"))
	}
	if config.Cache.RateLimitCacheSize == 0 {
		errorList = append(errorList, errors.New("rate limit cache size is required"))
	}

	// MFA Config validation
	issuerTrimmed := strings.TrimSpace(config.MFA.TOTP.Issuer)
	if issuerTrimmed == "" {
		errorList = append(errorList, errors.New("TOTP issuer is required"))
	}
	if issuerTrimmed == "Vayen Auth" {
		errorList = append(errorList, errors.New("TOTP issuer is set to default, set it to something else for security reasons"))
	}
	if config.MFA.TOTP.ImageWidth == 0 {
		errorList = append(errorList, errors.New("TOTP image width is required"))
	}
	if config.MFA.TOTP.ImageHeight == 0 {
		errorList = append(errorList, errors.New("TOTP image height is required"))
	}

	rpOriginsLen := len(config.MFA.WebAuthn.RelyingPartyOrigins)
	if rpOriginsLen == 0 {
		errorList = append(errorList, errors.New("webauthn relying party origins are required"))
	}
	if rpOriginsLen == 1 && config.MFA.WebAuthn.RelyingPartyOrigins[0] == "https://vayen.dev/auth" {
		errorList = append(errorList, errors.New("WebAuthn relying party origins are set to default, set them to something else for security reasons"))
	}

	if strings.TrimSpace(config.MFA.WebAuthn.RelyingPartyDisplayName) == "" {
		errorList = append(errorList, errors.New("webauthn relying party display name is required"))
	}

	return errorList
}

func ReadConfig(configFilePath string) (Config, error) {
	file, err := os.ReadFile(configFilePath)
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
