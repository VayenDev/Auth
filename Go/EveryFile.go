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
/*
 * Auth: argon2.go
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

package crypto

import (
	"github.com/alexedwards/argon2id"
)

func HashArgon2id(input string) (string, error) {
	return argon2id.CreateHash(input, argon2id.DefaultParams)
}

func VerifyArgon2id(input string, hash string) (bool, error) {
	return argon2id.ComparePasswordAndHash(input, hash)
}
/*
 * Auth: hmac.go
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

package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
)

const MacKeySize = 32

func NewMACKey() ([]byte, error) {
	key := make([]byte, MacKeySize)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func ComputeMAC(input, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(input)
	return mac.Sum(nil)
}

func VerifyMAC(input, hash, key []byte) bool {
	return hmac.Equal(hash, ComputeMAC(input, key))
}
/*
 * Auth: csrf.go
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

package crypto

import (
	"crypto/rand"
	"encoding/base64"
)

func GenerateCSRF() (string, error) {
	bytes := make([]byte, 32)

	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(bytes), nil
}
/*
 * Auth: session.go
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

package data

import (
	"auth/crypto"
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func CreateSessionTable(conn *pgx.Conn) error {
	const schema = `
        CREATE TABLE IF NOT EXISTS sessions (
            uuid UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            user_uuid UUID NOT NULL,
            mac_key BYTEA NOT NULL,
            created_at BIGINT NOT NULL,
            valid_for BIGINT NOT NULL,
            created_at_expires TIMESTAMPTZ NOT NULL GENERATED ALWAYS AS (
                to_timestamp(created_at::double precision / 1000000000) +
                (valid_for::text || ' seconds')::interval
            ) STORED,
            CONSTRAINT fk_user
                FOREIGN KEY (user_uuid) REFERENCES accounts(uuid)
                ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(created_at_expires);
        CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_uuid);
    `

	_, err := conn.Exec(context.Background(), schema)
	return err
}

var SessionCost = int64(32 + crypto.MacKeySize + 8 + 8)

type Session struct {
	UserUUID  uuid.UUID
	UUID      uuid.UUID
	MacKey    [crypto.MacKeySize]byte // HMAC SHA 256
	CreatedAt int64
	ValidFor  time.Duration
}

func (session Session) Expired() bool {
	return time.Now().UnixNano()-session.CreatedAt > int64(session.ValidFor)
}
/*
 * Auth: account.go
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

package data

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func CreateAccountTable(conn *pgx.Conn) error {
	const schema = `
        CREATE TABLE IF NOT EXISTS accounts (
            uuid UUID PRIMARY KEY DEFAULT gen_random_uuid() UNIQUE,
            username VARCHAR(32) NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            webhook_id UUID NOT NULL UNIQUE,
            recovery_codes JSONB NOT NULL DEFAULT '[]'
        );
        
        CREATE INDEX IF NOT EXISTS idx_webhook_id ON accounts(webhook_id);
    `

	_, err := conn.Exec(context.Background(), schema)
	return err
}

type Account struct {
	UUID          uuid.UUID
	Username      string
	PasswordHash  string
	WebhookID     uuid.UUID // A unique webhook ID for the account. It is used to receive notifications for e.g., password reset, ... without providing an e-mail address.
	RecoveryCodes []string
}
/*
 * Auth: mfa.go
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

package data

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	TOTPTableName     = "mfa_totp"
	WebAuthnTableName = "mfa_webauthn"
)

func CreateMFATable(conn *pgx.Conn) error {
	schema := fmt.Sprintf(`
		CREATE TABLE IF NOT EXISTS %s (
			uuid UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			user_uuid UUID NOT NULL REFERENCES accounts(uuid) ON DELETE CASCADE,
			secret TEXT,
		);
		CREATE TABLE IF NOT EXISTS %s (
			uuid UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			user_uuid UUID NOT NULL REFERENCES accounts(uuid) ON DELETE CASCADE,
			
		    credential_id BYTEA NOT NULL UNIQUE,
		    public_key TEXT NOT NULL,
		    attestation_type TEXT NOT NULL
		    sign_count INTEGER NOT NULL,
		    transports TEXT[] NOT NULL,
		    
		    -- Backup/Sync Flags (Passkeys)
		    backup_eligible boolean NOT NULL,
		    backup_state TEXT NOT NULL,
		);
		
		-- Indexes
		CREATE INDEX IF NOT EXISTS idx_mfa_totp_user_uuid ON mfa_totp(user_uuid);
		CREATE INDEX IF NOT EXISTS idx_mfa_webauthn_user_uuid ON mfa_webauthn(user_uuid);

		CREATE INDEX IF NOT EXISTS idx_mfa_webauthn_credential_id ON mfa_webauthn(credential_id);
		CREATE INDEX IF NOT EXISTS idx_mfa_webauthn_user ON mfa_webauthn(user_uuid)
    `, TOTPTableName, WebAuthnTableName)

	_, err := conn.Exec(context.Background(), schema)
	return err
}

type MFAMethod interface {
	GetTableName() string
}

func GetTableName[T MFAMethod]() string {
	var mfa T
	return mfa.GetTableName()
}

type MFA struct {
	MFAMethod
	UUID     uuid.UUID `db:"uuid"`
	UserUUID uuid.UUID `db:"user_uuid"`
}

type MFATimedOneTimePassword struct {
	MFA
	Secret string `db:"secret"`
}

func (m MFATimedOneTimePassword) GetTableName() string { return TOTPTableName }

type MFAWebAuthn struct {
	MFA
	CredentialID    uuid.UUID `db:"credential_id"`
	PublicKey       string    `db:"public_key"`
	AttestationType string    `db:"attestation_type"`
	SignCount       uint32    `db:"sign_count"`
	Transports      []string  `db:"transports"`

	// Passkey Backup Flags
	BackupEligible bool `db:"backup_eligible"`
	BackupState    bool `db:"backup_state"`
}

func (m MFAWebAuthn) GetTableName() string { return WebAuthnTableName }
/*
 * Auth: webauthn_user.go
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

package data

import (
	"github.com/go-webauthn/webauthn/webauthn"
)

type WebAuthnUser struct {
	Account     *Account
	Credentials []webauthn.Credential
}

func (user *WebAuthnUser) WebAuthnID() []byte {
	binary, _ := user.Account.UUID.MarshalBinary()
	return binary
}

func (user *WebAuthnUser) WebAuthnName() string {
	return user.Account.Username
}

func (user *WebAuthnUser) WebAuthnDisplayName() string {
	return user.Account.Username
}

func (user *WebAuthnUser) WebAuthnIcon() string {
	return ""
}

func (user *WebAuthnUser) WebAuthnCredentials() []webauthn.Credential {
	return user.Credentials
}
/*
 * Auth: rate_limiter.go
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

package mw

import (
	"auth/config"
	"auth/service"
	"net"
	"net/http"

	"github.com/dgraph-io/ristretto/v2"
	"golang.org/x/time/rate"
)

func RateLimitMiddleware(rateLimitCache *ristretto.Cache[[]byte, *rate.Limiter], config *config.Config, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := GetIdentifier(r)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
			return
		}

		rateLimiter, success := rateLimitCache.Get(id)
		if !success {
			http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
			return
		}

		if rateLimiter == nil {
			rateLimiter = rate.NewLimiter(rate.Every(config.RateLimit.Window), config.RateLimit.MaxRequests)
			rateLimitCache.Set(id, rateLimiter, 0)
		}

		if !rateLimiter.Allow() {
			http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func GetIdentifier(r *http.Request) ([]byte, error) {
	sessionCookie, err := GetSessionCookie(nil, r)
	if err == nil {
		retrievedUUID, _, err := service.SplitUUIDAndMAC(sessionCookie)
		if err != nil {
			ip, err := GetIp(r)
			if err != nil {
				return nil, err
			}
			return []byte(ip), nil
		}

		return retrievedUUID[:], nil
	}

	ip, err := GetIp(r)
	if err != nil {
		return nil, err
	}
	return []byte(ip), nil
}

func GetIp(r *http.Request) (string, error) {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return "", err
	}
	return ip, nil
}
/*
 * Auth: session_and_account_parsing.go
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

package mw

import (
	"auth/config"
	"auth/data"
	"auth/route"
	"auth/service"
	"context"
	"net/http"
	"strings"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func SessionAndAccountParsingMiddleware(config config.Config, logger *zerolog.Logger, sessionServiceSetup service.GeneralData[data.Session], accountServiceSetup service.GeneralData[data.Account], mfaServiceSetup service.GeneralData[data.MFAMethod], next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		ctx = context.WithValue(ctx, route.ConfigKey, config)
		ctx = context.WithValue(ctx, route.LoggerKey, logger)

		ctx = context.WithValue(ctx, route.SessionServiceSetupKey, sessionServiceSetup)
		ctx = context.WithValue(ctx, route.AccountServiceSetupKey, accountServiceSetup)
		ctx = context.WithValue(ctx, route.MFAServiceSetupKey, mfaServiceSetup)

		sessionCookie, _ := GetSessionCookie(w, r)

		if r.URL.Path == "/account/login" || r.URL.Path == "/account/register" {
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		sessionCookie, err := GetSessionCookie(w, r)
		if err != nil {
			return
		}

		retrievedUUID, macTag, err := service.SplitUUIDAndMAC(sessionCookie)
		if err != nil {
			http.Error(w, "Invalid authorization header", http.StatusUnauthorized)
			log.Err(err)
			return
		}
		ctx = context.WithValue(ctx, route.UUIDKey, retrievedUUID)
		ctx = context.WithValue(ctx, route.MacTagKey, macTag)

		session, err := service.GetSession(sessionServiceSetup, retrievedUUID)
		if err != nil {
			http.Error(w, "Invalid authorization header", http.StatusUnauthorized)
			log.Err(err)
			return
		}

		ctx = context.WithValue(ctx, route.SessionKey, session)

		if r.URL.Path == "/session/valid" {
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		if session.Expired() {
			http.Error(w, "Session expired", http.StatusUnauthorized)
			err := service.DeleteSession(sessionServiceSetup, retrievedUUID)
			if err != nil {
				log.Err(err)
			}
			return
		}

		account, err := service.GetAccount(accountServiceSetup, session.UserUUID)
		if err != nil {
			http.Error(w, "Failed to get account", http.StatusInternalServerError)
			log.Err(err)
			return
		}

		ctx = context.WithValue(ctx, route.AccountKey, account)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}

func GetSessionCookie(w http.ResponseWriter, r *http.Request) (string, error) {
	sessionCookie, err := route.ReadSessionHttpCookie(r)
	if err != nil {
		if w != nil {
			http.Error(w, "Failed to read session cookie", http.StatusInternalServerError)
			log.Err(err)
		}
		return "", err
	}

	if strings.TrimSpace(sessionCookie) == "" || !strings.HasPrefix(sessionCookie, "VA:") {
		if w != nil {
			http.Error(w, "Authorization header is required", http.StatusUnauthorized)
		}
		return "", err
	}

	return sessionCookie, nil
}
/*
 * Auth: csrf.go
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

package mw

import (
	"net/http"
)

func CSRFMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}

		if r.URL.Path == "/account/login" || r.URL.Path == "/account/register" {
			next.ServeHTTP(w, r)
			return
		}

		headerToken := r.Header.Get("X-CSRF-Token")
		if headerToken == "" {
			http.Error(w, "CSRF token missing from header", http.StatusForbidden)
			return
		}

		cookie, err := r.Cookie("csrf_token")
		if err != nil {
			http.Error(w, "CSRF cookie missing", http.StatusForbidden)
			return
		}
		cookieToken := cookie.Value

		if headerToken != cookieToken {
			http.Error(w, "Invalid CSRF token", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}
/*
 * Auth: datasizes.go
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

package other

const (
	KiB = 1 << 10
	MiB = 1 << 20
	GiB = 1 << 30
	TiB = 1 << 40
	PiB = 1 << 50
	EiB = 1 << 60
)
/*
 * Auth: totp_route.go
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

package mfa

import (
	"auth/data"
	"auth/route"
	"auth/service"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"image/png"
	"io"
	"net/http"
	"strings"

	"github.com/rs/zerolog/log"
)

func HandleHasTOTP(writer http.ResponseWriter, request *http.Request) {
	_, _, accountContext, mfaContext := route.GetKeysFromContext(request.Context())
	account := accountContext.Account

	hasTOTP, err := service.HasMFA[data.MFATimedOneTimePassword](mfaContext.ServiceSetup, account.UUID)
	if err != nil {
		http.Error(writer, "Failed to check if account has TOTP", http.StatusInternalServerError)
		log.Err(err)
		return
	}

	writer.WriteHeader(http.StatusOK)
	fmt.Fprintf(writer, "%t", hasTOTP)
	return
}
func HandleValidateTOTP(writer http.ResponseWriter, request *http.Request) {
	_, _, accountContext, mfaContext := route.GetKeysFromContext(request.Context())

	totpCode, err := GetTOTPCode(request.Body)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		log.Err(err)
		return
	}

	valid, err := service.ValidateTOTP(mfaContext.ServiceSetup, accountContext.Account.UUID, totpCode)
	if err != nil {
		http.Error(writer, "Failed to validate TOTP", http.StatusInternalServerError)
		log.Err(err)
	}

	writer.WriteHeader(http.StatusOK)
	fmt.Fprintf(writer, "%t", valid)
	return
}

func HandleActivateTOTP(writer http.ResponseWriter, request *http.Request) {
	generalContext, _, accountContext, mfaContext := route.GetKeysFromContext(request.Context())
	logger := generalContext.Logger
	response := route.Respond(writer)

	_, key, err := service.AddMFATimedOneTimePassword(mfaContext.ServiceSetup, accountContext.Account.UUID, accountContext.Account.Username)
	if err != nil {
		response.Dict("error", response.AnErr("secret", err)).Send()
		writer.WriteHeader(http.StatusInternalServerError)
		logger.Err(err)
		return
	}

	response.Dict("success", response.Str("secret", key.Secret()))

	var buffer bytes.Buffer
	img, err := key.Image(generalContext.Config.MFA.TOTP.ImageWidth, generalContext.Config.MFA.TOTP.ImageHeight)
	if err != nil {
		logger.Err(err).Msg("Failed to generate TOTP QR code")
		response.Dict("error", response.AnErr("qr_encoded", err)).Send()
		writer.WriteHeader(http.StatusOK)
		return
	}

	err = png.Encode(&buffer, img)
	if err != nil {
		logger.Err(err).Msg("Failed to encode TOTP QR code")
		response.Dict("error", response.AnErr("qr_encoded", err)).Send()
		writer.WriteHeader(http.StatusOK)
		return
	}

	response.Dict("success", response.Str("qr_encoded", "data:image/png;base64,"+base64.StdEncoding.EncodeToString(buffer.Bytes()))).Send()
	writer.WriteHeader(http.StatusOK)
	return
}

func HandleDeactivateTOTP(writer http.ResponseWriter, request *http.Request) {
	_, _, accountContext, mfaContext := route.GetKeysFromContext(request.Context())

	err := service.RemoveMFAByUserID[data.MFATimedOneTimePassword](mfaContext.ServiceSetup, accountContext.Account.UUID)
	if err != nil {
		http.Error(writer, "Failed to remove TOTP", http.StatusInternalServerError)
		log.Err(err)
		return
	}

	writer.WriteHeader(http.StatusOK)
	return
}

func GetTOTPCode(bodyRC io.ReadCloser) (string, error) {
	defer bodyRC.Close()

	var data struct {
		Code string `json:"code"`
	}

	if err := json.NewDecoder(bodyRC).Decode(&data); err != nil {
		return "", err
	}
	if strings.TrimSpace(data.Code) == "" {
		return "", errors.New("totp code cannot be empty")
	}

	return data.Code, nil
}
/*
 * Auth: session_route.go
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

package route

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"src/crypto"
	"src/service"
	"time"

	"github.com/rs/zerolog/log"
)

func HandleSessionValid(writer http.ResponseWriter, request *http.Request) {
	_, sessionContext, _, _ := GetKeysFromContext(request.Context())

	isValid := crypto.VerifyMAC([]byte(fmt.Sprintf("%s:%d", sessionContext.UUID, sessionContext.Session.ValidFor)), sessionContext.MacTag[:], sessionContext.Session.MacKey[:])

	writer.WriteHeader(http.StatusOK)
	if isValid {
		if _, err := fmt.Fprint(writer, "valid"); err != nil {
			return
		}
	} else {
		if _, err := fmt.Fprint(writer, "invalid"); err != nil {
			return
		}
	}
}
func HandleSessionExpired(writer http.ResponseWriter, request *http.Request) {
	_, sessionContext, _, _ := GetKeysFromContext(request.Context())
	expired := sessionContext.Session.Expired()

	writer.WriteHeader(http.StatusOK)
	if expired {
		if _, err := fmt.Fprint(writer, "expired"); err != nil {
			log.Err(err)
		}
	} else {
		if _, err := fmt.Fprint(writer, "valid"); err != nil {
			log.Err(err)
		}
	}

	return
}
func HandleSessionInvalidate(writer http.ResponseWriter, request *http.Request) {
	_, sessionContext, _, _ := GetKeysFromContext(request.Context())
	err := service.DeleteSession(sessionContext.ServiceSetup, sessionContext.UUID)
	if err != nil {
		http.Error(writer, "Failed to delete session", http.StatusInternalServerError)
		log.Err(err)
		return
	}
}

func BuildSessionHttpCookie(token string, validFor time.Duration) *http.Cookie {
	var maxAge int
	if validFor < 0 {
		maxAge = -1
	} else {
		maxAge = int(validFor / time.Second)
	}

	var expires time.Time
	if maxAge == -1 {
		expires = time.Unix(0, 0)
	} else {
		expires = time.Now().Add(validFor)
	}

	return &http.Cookie{
		Name:     "session",
		Value:    base64.URLEncoding.EncodeToString([]byte(token)),
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   maxAge,
		Expires:  expires,
	}
}

func ReadSessionHttpCookie(request *http.Request) (string, error) {
	cookie, err := request.Cookie("session")
	if err != nil {
		return "", err
	}

	decoded, err := base64.URLEncoding.DecodeString(cookie.Value)
	if err != nil {
		return "", err
	}

	return string(decoded), nil
}
/*
 * Auth: context.go
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

package route

import (
	"auth/config"
	"auth/data"
	"auth/service"
	"context"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

type contextKey string

const (
	ConfigKey = contextKey("config")
	LoggerKey = contextKey("logger")

	SessionServiceSetupKey = contextKey("session_service_setup")
	AccountServiceSetupKey = contextKey("account_service_setup")
	MFAServiceSetupKey     = contextKey("mfa_service_setup")

	UUIDKey    = contextKey("session_uuid")
	MacTagKey  = contextKey("session_mac_tag")
	SessionKey = contextKey("session")
	AccountKey = contextKey("account")
)

type GeneralContext struct {
	Config config.Config
	Logger *zerolog.Logger
}

type SessionContext struct {
	ServiceSetup service.GeneralData[data.Session]
	Session      data.Session
	UUID         uuid.UUID
	MacTag       []byte
}

type AccountContext struct {
	ServiceSetup service.GeneralData[data.Account]
	Account      data.Account
}

type TOTPContext struct {
	ServiceSetup service.GeneralData[data.MFAMethod]
}

func GetKeysFromContext(context context.Context) (GeneralContext, SessionContext, AccountContext, TOTPContext) {
	retrievedConfig := context.Value(ConfigKey).(config.Config)
	retrievedLogger := context.Value(LoggerKey).(*zerolog.Logger)

	retrievedSessionUUID := context.Value(UUIDKey).(uuid.UUID)
	retrievedSessionMacTag := context.Value(MacTagKey).([]byte)

	retrievedSessionServiceSetup := context.Value(SessionServiceSetupKey).(service.GeneralData[data.Session])
	retrievedSession := context.Value(SessionKey).(data.Session)

	retrievedAccountServiceSetup := context.Value(AccountServiceSetupKey).(service.GeneralData[data.Account])
	retrievedAccount := context.Value(AccountKey).(data.Account)

	retrievedMFAServiceSetup := context.Value(MFAServiceSetupKey).(service.GeneralData[data.MFAMethod])

	return GeneralContext{
			Config: retrievedConfig,
			Logger: retrievedLogger,
		}, SessionContext{
			ServiceSetup: retrievedSessionServiceSetup,
			Session:      retrievedSession,
			UUID:         retrievedSessionUUID,
			MacTag:       retrievedSessionMacTag,
		}, AccountContext{
			ServiceSetup: retrievedAccountServiceSetup,
			Account:      retrievedAccount,
		}, TOTPContext{
			ServiceSetup: retrievedMFAServiceSetup,
		}
}
/*
 * Auth: account_route.go
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

package route

import (
	"auth/crypto"
	"auth/service"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

func HandleAccountRegister(writer http.ResponseWriter, request *http.Request) {
	username, password, err := GetUsernameAndPasswordFromBody(request.Body)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		log.Err(err)
		return
	}

	_, _, accountContext, _ := GetKeysFromContext(request.Context())
	_, err = service.CreateAccount(accountContext.ServiceSetup, username, password)
	if err != nil {
		http.Error(writer, "Failed to create account", http.StatusInternalServerError)
		log.Err(err)
		return
	}

	writer.WriteHeader(http.StatusOK)
	return
}
func HandleAccountLogin(writer http.ResponseWriter, request *http.Request) {
	username, password, err := GetUsernameAndPasswordFromBody(request.Body)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		log.Err(err)
		return
	}

	generalContext, sessionContext, accountContext, _ := GetKeysFromContext(request.Context())

	sessionFormatted, err := service.AccountLogin(accountContext.ServiceSetup, sessionContext.ServiceSetup, generalContext.Config.Session.ValidFor, username, password)
	if err != nil {
		http.Error(writer, "Failed to login", http.StatusInternalServerError)
		log.Err(err)
		return
	}
	csrfToken, err := crypto.GenerateCSRF()
	if err != nil {
		http.Error(writer, "Failed to generate CSRF token", http.StatusInternalServerError)
		log.Err(err)
		return
	}

	http.SetCookie(writer, BuildSessionHttpCookie(sessionFormatted, generalContext.Config.Session.ValidFor))

	http.SetCookie(writer, buildCsrfCookie(csrfToken, generalContext.Config.Session.ValidFor))

	writer.WriteHeader(http.StatusOK)
	return
}
func HandleAccountChangePassword(writer http.ResponseWriter, request *http.Request) {
	_, newPassword, err := GetUsernameAndPasswordFromBody(request.Body)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		log.Err(err)
		return
	}

	_, sessionContext, accountContext, _ := GetKeysFromContext(request.Context())

	err = service.UpdatePassword(accountContext.ServiceSetup, accountContext.Account.UUID, newPassword)
	if err != nil {
		http.Error(writer, "Failed to update password", http.StatusInternalServerError)
		log.Err(err)
		return
	}

	http.SetCookie(writer, BuildSessionHttpCookie(service.BuildSessionString(sessionContext.UUID, sessionContext.MacTag), -1)) // Invalidating ALL sessions too
	http.SetCookie(writer, buildCsrfCookie("", -1))

	writer.WriteHeader(http.StatusOK)
	return
}

func HandleAccountDelete(writer http.ResponseWriter, request *http.Request) {
	_, sessionContext, accountContext, _ := GetKeysFromContext(request.Context())

	err := service.DeleteAccount(accountContext.ServiceSetup, accountContext.Account.UUID)
	if err != nil {
		http.Error(writer, "Failed to delete session", http.StatusInternalServerError)
		log.Err(err)
		return
	}

	http.SetCookie(writer, BuildSessionHttpCookie(service.BuildSessionString(sessionContext.UUID, sessionContext.MacTag), -1)) // Invalidating ALL sessions too
	http.SetCookie(writer, buildCsrfCookie("", -1))

	writer.WriteHeader(http.StatusOK)
	return
}

func HandleAccountLogout(writer http.ResponseWriter, request *http.Request) {
	_, sessionContext, _, _ := GetKeysFromContext(request.Context())

	err := service.DeleteSession(sessionContext.ServiceSetup, sessionContext.UUID)
	if err != nil {
		http.Error(writer, "Failed to delete session", http.StatusInternalServerError)
		log.Err(err)
	}

	http.SetCookie(writer, BuildSessionHttpCookie(service.BuildSessionString(sessionContext.UUID, sessionContext.MacTag), -1)) // Invalidating ALL sessions too
	http.SetCookie(writer, buildCsrfCookie("", -1))

	writer.WriteHeader(http.StatusNoContent)
	return
}

func GetUsernameAndPasswordFromBody(bodyRC io.ReadCloser) (string, string, error) {
	defer bodyRC.Close()

	var data struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(bodyRC).Decode(&data); err != nil {
		return "", "", err
	}

	if strings.TrimSpace(data.Password) == "" {
		return "", "", errors.New("(new) password cannot be empty")
	}

	return data.Username, data.Password, nil
}

func buildCsrfCookie(token string, validFor time.Duration) *http.Cookie {
	var maxAge int
	if validFor < 0 {
		maxAge = -1
	} else {
		maxAge = int(validFor / time.Second)
	}

	var expires time.Time
	if maxAge == -1 {
		expires = time.Unix(0, 0)
	} else {
		expires = time.Now().Add(validFor)
	}

	return &http.Cookie{
		Name:     "csrf_token", // Different name
		Value:    token,
		Path:     "/",
		HttpOnly: false, // <-- MUST be false so JavaScript can read it
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   maxAge,
		Expires:  expires,
	}
}
/*
 * Auth: response_json.go
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

package route

import (
	"net/http"

	"github.com/rs/zerolog"
)

func Respond(writer http.ResponseWriter) *zerolog.Event {
	writer.Header().Set("Content-Type", "application/json")
	logger := zerolog.New(writer).Level(zerolog.Disabled).With().Timestamp().Logger()
	return logger.Log()
}
/*
 * Auth: session_service.go
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

package service

import (
	"auth/crypto"
	"auth/data"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

func GetSession(setup GeneralData[data.Session], uuid uuid.UUID) (data.Session, error) {
	err := setup.Validate()
	if err != nil {
		return data.Session{}, err
	}

	if value, found := setup.Cache.Get(uuid[:]); found {
		return value, nil
	}

	const query = "SELECT * FROM sessions WHERE uuid = $1"

	var session data.Session
	err = setup.Database.QueryRow(setup.DBContext, query, uuid).Scan(&session)
	if err != nil {
		return data.Session{}, err
	}

	if session.Expired() {
		return data.Session{}, errors.New("session expired")
	}

	return session, nil
}

func GetSessionMACKey(setup GeneralData[data.Session], uuid uuid.UUID) ([crypto.MacKeySize]byte, error) {
	err := setup.Validate()
	if err != nil {
		return [crypto.MacKeySize]byte{}, err
	}

	query := "SELECT mac_key FROM sessions WHERE uuid = $1"
	var macKey [crypto.MacKeySize]byte
	err = setup.Database.QueryRow(setup.DBContext, query, uuid).Scan(&macKey)
	if err != nil {
		return [crypto.MacKeySize]byte{}, err
	}

	return macKey, nil
}

func CreateSession(setup GeneralData[data.Session], ownerUUID uuid.UUID, validFor time.Duration) (data.Session, []byte, error) {
	err := setup.Validate()
	if err != nil {
		return data.Session{}, nil, err
	}

	key, err := crypto.NewMACKey()
	if err != nil {
		return data.Session{}, nil, err
	}
	generatedUUID := uuid.New()
	mac := crypto.ComputeMAC([]byte(fmt.Sprintf("%s:%d", generatedUUID, validFor)), key)

	session := data.Session{
		UUID:      generatedUUID,
		MacKey:    [crypto.MacKeySize]byte(key),
		CreatedAt: time.Now().UnixNano(),
		ValidFor:  validFor,
	}

	query := "INSERT INTO sessions (uuid, user_uuid, mac_key, created_at, valid_for) VALUES ($1, $2, $3, $4, $5)"
	_, err = setup.Database.Exec(setup.DBContext, query, session.UUID, ownerUUID, session.MacKey, session.CreatedAt, session.ValidFor)
	if err != nil {
		return data.Session{}, nil, err
	}

	added := setup.Cache.Set(generatedUUID[:], session, data.SessionCost)
	if !added {
		log.Error().Msg("Failed to add session to cache")
	}

	return session, mac, nil
}

func DeleteSession(setup GeneralData[data.Session], uuid uuid.UUID) error {
	err := setup.Validate()
	if err != nil {
		return err
	}

	setup.Cache.Del(uuid[:])

	query := "DELETE FROM sessions WHERE uuid = $1"
	_, err = setup.Database.Exec(setup.DBContext, query, uuid)
	return err
}

func SplitUUIDAndMAC(uuidAndMac string) (uuid.UUID, []byte, error) {
	result := strings.Split(uuidAndMac, ".")

	if len(result) != 2 {
		return uuid.Nil, []byte{}, errors.New("invalid uuid and mac")
	}

	parsedUUID, err := uuid.Parse(strings.TrimPrefix(result[0], "VA:"))
	if err != nil {
		return uuid.Nil, []byte{}, err
	}

	macTag := []byte(result[1])
	return parsedUUID, macTag, nil
}

func BuildSessionString(uuid uuid.UUID, macTag []byte) string {
	return fmt.Sprintf("VA:%s.%s", uuid, macTag)
}
/*
 * Auth: account_service.go
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

package service

import (
	"auth/crypto"
	"auth/data"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

func GetAccount(setup GeneralData[data.Account], uuid uuid.UUID) (data.Account, error) {
	err := setup.Validate()
	if err != nil {
		return data.Account{}, err
	}

	if value, found := setup.Cache.Get(uuid[:]); found {
		return value, nil
	}

	const query = "SELECT 1 FROM accounts WHERE uuid = $1"

	var account data.Account
	err = setup.Database.QueryRow(setup.DBContext, query, uuid).Scan(&account)
	if err != nil {
		return data.Account{}, err
	}

	return account, nil
}

func GetAccountByUsername(setup GeneralData[data.Account], username string) (data.Account, error) {
	err := setup.Validate()
	if err != nil {
		return data.Account{}, err
	}

	const query = "SELECT 1 FROM accounts WHERE username = $1"
	var account data.Account
	err = setup.Database.QueryRow(setup.DBContext, query, username).Scan(&account)
	if err != nil {
		return data.Account{}, err
	}

	return account, nil
}

func GetAccountBySessionUUID(setup GeneralData[data.Account], sessionUUID uuid.UUID) (data.Account, error) {
	err := setup.Validate()
	if err != nil {
		return data.Account{}, err
	}

	const query = "SELECT 1 FROM accounts WHERE uuid = (SELECT user_uuid FROM sessions WHERE uuid = $1)"
	var account data.Account
	err = setup.Database.QueryRow(setup.DBContext, query, sessionUUID).Scan(&account)
	if err != nil {
		return data.Account{}, err
	}

	return account, nil
}

func GetAccountByWebhookID(setup GeneralData[data.Account], webhookID uuid.UUID) (data.Account, error) {
	err := setup.Validate()
	if err != nil {
		return data.Account{}, err
	}

	const query = "SELECT 1 FROM accounts WHERE webhook_id = $1"
	var account data.Account
	err = setup.Database.QueryRow(setup.DBContext, query, webhookID).Scan(&account)
	if err != nil {
		return data.Account{}, err
	}

	return account, nil
}

func GetAccountRecoveryCodes(setup GeneralData[data.Account], uuid uuid.UUID) ([]string, error) {
	err := setup.Validate()
	if err != nil {
		return nil, err
	}

	account, err := GetAccount(setup, uuid)
	if err != nil {
		return nil, err
	}

	return account.RecoveryCodes, nil
}

func CheckPassword(setup GeneralData[data.Account], uuid uuid.UUID, unhashedPassword string) (bool, error) {
	err := setup.Validate()
	if err != nil {
		return false, err
	}

	const query = "SELECT password_hash FROM accounts WHERE uuid = $1"
	var passwordHash string
	err = setup.Database.QueryRow(setup.DBContext, query, uuid).Scan(&passwordHash)
	if err != nil {
		return false, err
	}

	if strings.TrimSpace(passwordHash) == "" {
		return false, nil
	}

	result, err := crypto.VerifyArgon2id(unhashedPassword, passwordHash)
	if err != nil {
		return false, err
	}

	return result, nil
}

func UpdatePassword(setup GeneralData[data.Account], uuid uuid.UUID, newPassword string) error {
	err := setup.Validate()
	if err != nil {
		return err
	}

	hashedPassword, err := crypto.HashArgon2id(newPassword)
	if err != nil {
		return err
	}
	query := "UPDATE accounts SET password_hash = $1 WHERE uuid = $2; DELETE FROM sessions WHERE user_uuid = $2"
	_, err = setup.Database.Exec(setup.DBContext, query, hashedPassword, uuid)
	return err
}

func AccountLogin(setup GeneralData[data.Account], sss GeneralData[data.Session], validFor time.Duration, username string, password string) (string, error) {
	err := setup.Validate()
	if err != nil {
		return "", err
	}

	const query = "SELECT uuid, password_hash FROM accounts WHERE username = $1"
	var (
		queriedUUID    uuid.UUID
		hashedPassword string
	)
	err = setup.Database.QueryRow(setup.DBContext, query, username).Scan(&queriedUUID, &hashedPassword)
	if err != nil {
		return "", err
	}

	result, err := crypto.VerifyArgon2id(password, hashedPassword)
	if err != nil {
		return "", err
	}

	if !result {
		return "", errors.New("invalid credentials")
	}

	session, mac, err := CreateSession(sss, queriedUUID, validFor)
	if err != nil {
		return "", err
	}

	return BuildSessionString(session.UUID, mac), nil
}

func CreateAccount(setup GeneralData[data.Account], username string, password string) (data.Account, error) {
	err := setup.Validate()
	if err != nil {
		return data.Account{}, err
	}

	generatedUUID := uuid.New()
	hashedPassword, err := crypto.HashArgon2id(password)
	if err != nil {
		return data.Account{}, err
	}
	webhookID := uuid.New()
	recoveryCodes, err := GenerateAccountRecoveryCodes(5)
	if err != nil {
		return data.Account{}, err
	}

	query := "INSERT INTO accounts (uuid, username, password_hash, webhook_id, recovery_codes) VALUES ($1, $2, $3, $4, $5)"
	_, err = setup.Database.Exec(setup.DBContext, query, generatedUUID, username, hashedPassword, webhookID, recoveryCodes)
	if err != nil {
		return data.Account{}, err
	}

	account := data.Account{
		UUID:          generatedUUID,
		Username:      username,
		PasswordHash:  hashedPassword,
		WebhookID:     webhookID,
		RecoveryCodes: recoveryCodes,
	}
	added := setup.Cache.Set(generatedUUID[:], account, 0)
	if !added {
		log.Error().Msg("Failed to add session to cache")
	}

	return account, nil
}

func GenerateAccountRecoveryCodes(n int) ([]string, error) {
	codes := make([]string, n)
	for i := range codes {
		b := make([]byte, 10)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		codes[i] = strings.ToUpper(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b))
		// e.g. X7K9P2M4Q1R8
	}
	return codes, nil
}

func DeleteAccount(setup GeneralData[data.Account], uuid uuid.UUID) error {
	err := setup.Validate()
	if err != nil {
		return err
	}

	setup.Cache.Del(uuid[:])

	query := "DELETE FROM accounts WHERE uuid = $1"
	_, err = setup.Database.Exec(setup.DBContext, query, uuid)
	return err
}
/*
 * Auth: common.go
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

package service

import (
	"auth/config"
	"context"
	"errors"

	"github.com/dgraph-io/ristretto/v2"
	"github.com/jackc/pgx/v5/pgxpool"
)

type GeneralData[T any] struct {
	Config    config.Config
	Database  *pgxpool.Pool
	DBContext context.Context
	Cache     *ristretto.Cache[[]byte, T]
}

func (setup GeneralData[T]) Validate() error {
	if setup.Database == nil {
		return errors.New("database is required")
	}
	if setup.Cache == nil {
		return errors.New("cache is required")
	}
	return nil
}
/*
 * Auth: mfa_webauthn_service.go
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

package service

// TODO: Implement
/*
 * Auth: mfa_totp_service.go
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

package service

import (
	"auth/data"

	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/rs/zerolog/log"
)

func AddMFATimedOneTimePassword(setup GeneralData[data.MFAMethod], userUUID uuid.UUID, username string) (data.MFATimedOneTimePassword, *otp.Key, error) {
	err := setup.Validate()
	if err != nil {
		return data.MFATimedOneTimePassword{}, nil, err
	}

	generatedUUID := uuid.New()

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      setup.Config.MFA.TOTP.Issuer,
		AccountName: username,
	})
	if err != nil {
		return data.MFATimedOneTimePassword{}, nil, err
	}
	secret := key.Secret()

	query := "INSERT INTO mfa_totp (generatedUUID, user_uuid, secret) VALUES ($1, $2, $3)"
	_, err = setup.Database.Exec(setup.DBContext, query, generatedUUID, userUUID, secret)
	if err != nil {
		return data.MFATimedOneTimePassword{}, nil, err
	}

	mfa := data.MFATimedOneTimePassword{
		Secret: secret,
	}
	mfa.UUID = generatedUUID
	mfa.UserUUID = userUUID

	added := setup.Cache.Set(generatedUUID[:], mfa, 0)
	if !added {
		log.Error().Msg("Failed to add mfa to cache")
	}

	return mfa, key, nil
}

func ValidateTOTP(setup GeneralData[data.MFAMethod], userUUID uuid.UUID, token string) (bool, error) {
	mfa, err := GetMFAByUserID[data.MFATimedOneTimePassword](setup, userUUID)
	if err != nil {
		return false, err
	}
	return totp.Validate(token, mfa.Secret), nil
}
/*
 * Auth: mfa_common_service.go
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

package service

import (
	"auth/data"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

func GetMFA[T data.MFAMethod](setup GeneralData[data.MFAMethod], uuid uuid.UUID) (T, error) {
	err := setup.Validate()
	if err != nil {
		return *new(T), err
	}

	if cacheValue, found := setup.Cache.Get(uuid[:]); found {
		mfa, ok := cacheValue.(T)
		if ok {
			return mfa, nil
		}
		return *new(T), errors.New("cache value is not of type T")
	}

	query := fmt.Sprintf("SELECT * FROM %s WHERE uuid = $1", data.GetTableName[T]())

	var mfa T
	err = setup.Database.QueryRow(setup.DBContext, query, uuid).Scan(&mfa)
	if err != nil {
		return *new(T), err
	}

	return mfa, nil
}

func GetMFAByUserID[T data.MFAMethod](setup GeneralData[data.MFAMethod], userUuid uuid.UUID) (T, error) {
	err := setup.Validate()
	if err != nil {
		return *new(T), err
	}

	query := fmt.Sprintf("SELECT * FROM %s WHERE user_uuid = $1", data.GetTableName[T]())

	var mfa T
	err = setup.Database.QueryRow(setup.DBContext, query, userUuid).Scan(&mfa)
	if err != nil {
		return *new(T), err
	}

	return mfa, nil
}

func RemoveMFA[T data.MFAMethod](setup GeneralData[data.MFAMethod], uuid uuid.UUID) error {
	err := setup.Validate()
	if err != nil {
		return err
	}

	setup.Cache.Del(uuid[:])

	query := fmt.Sprintf("DELETE FROM %s WHERE uuid = $1", data.GetTableName[T]())
	_, err = setup.Database.Exec(setup.DBContext, query, uuid)
	return err
}

func RemoveMFAByUserID[T data.MFAMethod](setup GeneralData[data.MFAMethod], userUuid uuid.UUID) error {
	err := setup.Validate()
	if err != nil {
		return err
	}

	query := fmt.Sprintf("DELETE FROM %s WHERE user_uuid = $1", data.GetTableName[T]())
	_, err = setup.Database.Exec(setup.DBContext, query, userUuid)
	return err
}

func HasMFA[T data.MFAMethod](setup GeneralData[data.MFAMethod], uuid uuid.UUID) (bool, error) {
	err := setup.Validate()
	if err != nil {
		return false, err
	}

	query := fmt.Sprintf("SELECT EXISTS(SELECT 1 FROM %s WHERE uuid = $1)", data.GetTableName[T]())
	var exists bool
	err = setup.Database.QueryRow(setup.DBContext, query, uuid).Scan(&exists)
	if err != nil {
		return false, err
	}

	return exists, err
}
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
