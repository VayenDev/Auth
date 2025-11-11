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
	"context"
	"errors"
	"fmt"
	"src/crypto"
	"src/data"
	"strings"
	"time"

	"github.com/dgraph-io/ristretto/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/rs/zerolog/log"
)

type AccountServiceSetup struct {
	Database  *pgx.Conn
	DBContext context.Context
	Cache     *ristretto.Cache[[]byte, data.Account]
}

func (setup AccountServiceSetup) Validate() error {
	if setup.Database == nil {
		return errors.New("database is required")
	}
	if setup.Cache == nil {
		return errors.New("cache is required")
	}
	return nil
}

func GetAccount(setup AccountServiceSetup, uuid uuid.UUID) (data.Account, error) {
	err := setup.Validate()
	if err != nil {
		return data.Account{}, err
	}

	if value, found := setup.Cache.Get(uuid[:]); found {
		return value, nil
	}

	const query = "SELECT * FROM accounts WHERE uuid = $1"

	var account data.Account
	err = setup.Database.QueryRow(setup.DBContext, query, uuid).Scan(&account)
	if err != nil {
		return data.Account{}, err
	}

	return account, nil
}

func CheckPassword(setup AccountServiceSetup, uuid uuid.UUID, unhashedPassword string) (bool, error) {
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

func UpdatePassword(setup AccountServiceSetup, uuid uuid.UUID, newPassword string) error {
	err := setup.Validate()
	if err != nil {
		return err
	}

	hashedPassword, err := crypto.HashArgon2id(newPassword)
	if err != nil {
		return err
	}
	query := "UPDATE accounts SET password_hash = $1 WHERE uuid = $2"
	_, err = setup.Database.Exec(setup.DBContext, query, hashedPassword, uuid)
	return err
}

func AccountLogin(setup AccountServiceSetup, sss SessionServiceSetup, validFor time.Duration, username string, password string) (string, error) {
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

	return fmt.Sprintf("VA:%s.%s", session.UUID, mac), nil
}

func CreateAccount(setup AccountServiceSetup, username string, password string) (data.Account, error) {
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

	query := "INSERT INTO accounts (uuid, username, password_hash, webhook_id) VALUES ($1, $2, $3, $4)"
	_, err = setup.Database.Exec(setup.DBContext, query, generatedUUID, username, hashedPassword, webhookID)
	if err != nil {
		return data.Account{}, err
	}

	account := data.Account{
		UUID:         generatedUUID,
		Username:     username,
		PasswordHash: hashedPassword,
		WebhookID:    webhookID,
	}
	added := setup.Cache.Set(generatedUUID[:], account, 0)
	if !added {
		log.Error().Msg("Failed to add session to cache")
	}

	return account, nil
}

func DeleteAccount(setup AccountServiceSetup, uuid uuid.UUID) error {
	err := setup.Validate()
	if err != nil {
		return err
	}

	setup.Cache.Del(uuid[:])

	query := "DELETE FROM accounts WHERE uuid = $1"
	_, err = setup.Database.Exec(setup.DBContext, query, uuid)
	return err
}
