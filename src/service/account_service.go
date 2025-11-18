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
	"crypto/rand"
	"encoding/base32"
	"errors"
	"src/crypto"
	"src/data"
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

	const query = "SELECT * FROM accounts WHERE uuid = $1"

	var account data.Account
	err = setup.Database.QueryRow(setup.DBContext, query, uuid).Scan(&account)
	if err != nil {
		return data.Account{}, err
	}

	return account, nil
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
