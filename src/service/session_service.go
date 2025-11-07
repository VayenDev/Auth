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
	"context"
	"errors"
	"fmt"
	"src"
	"src/crypto"
	"strings"
	"time"

	"github.com/dgraph-io/ristretto/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/rs/zerolog/log"
)

type SessionServiceSetup struct {
	Database  *pgx.Conn
	DBContext context.Context
	Cache     *ristretto.Cache[[]byte, src.Session]
}

func (setup SessionServiceSetup) Validate() error {
	if setup.Database == nil {
		return errors.New("database is required")
	}
	if setup.Cache == nil {
		return errors.New("cache is required")
	}
	return nil
}

func GetSession(setup SessionServiceSetup, uuid uuid.UUID) (src.Session, error) {
	err := setup.Validate()
	if err != nil {
		return src.Session{}, err
	}

	if value, found := setup.Cache.Get(uuid[:]); found {
		return value, nil
	}

	query := "SELECT * FROM sessions WHERE uuid = $1"

	var session src.Session
	err = setup.Database.QueryRow(setup.DBContext, query, uuid).Scan(&session)
	if err != nil {
		return src.Session{}, err
	}

	if session.Expired() {
		return src.Session{}, errors.New("session expired")
	}

	return session, nil
}

func CreateSession(setup SessionServiceSetup, validFor time.Duration) (src.Session, []byte, error) {
	err := setup.Validate()
	if err != nil {
		return src.Session{}, nil, err
	}

	key, err := crypto.NewMACKey()
	if err != nil {
		return src.Session{}, nil, err
	}
	generatedUUID := uuid.New()
	mac := crypto.ComputeMAC([]byte(fmt.Sprintf("%s:%d", generatedUUID, validFor)), key)

	session := src.Session{
		UUID:     generatedUUID,
		MacKey:   [crypto.MacKeySize]byte(key),
		CreateAt: time.Now().Unix(),
		ValidFor: validFor,
	}

	query := "INSERT INTO sessions (uuid, mac_key, create_at, valid_for) VALUES ($1, $2, $3, $4)"
	_, err = setup.Database.Exec(setup.DBContext, query, session.UUID, session.MacKey, session.CreateAt, session.ValidFor)
	if err != nil {
		return src.Session{}, nil, err
	}

	cost := int64(16 + crypto.MacKeySize + 8 + 8)
	added := setup.Cache.Set(generatedUUID[:], session, cost)
	if !added {
		log.Error().Msg("Failed to add session to cache")
	}

	return session, mac, nil
}

func DeleteSession(setup SessionServiceSetup, uuid uuid.UUID) error {
	err := setup.Validate()
	if err != nil {
		return err
	}

	setup.Cache.Del(uuid[:])

	query := "DELETE FROM sessions WHERE uuid = $1"
	_, err = setup.Database.Exec(setup.DBContext, query, uuid)
	return err
}

func SplitUUIDAndMAC(uuidAndMac string) (uuid.UUID, [crypto.MacKeySize]byte, error) {
	result := strings.Split(uuidAndMac, ".")

	if len(result) != 2 {
		return uuid.Nil, [crypto.MacKeySize]byte{}, errors.New("invalid uuid and mac")
	}

	parsedUUID, err := uuid.Parse(result[0])
	if err != nil {
		return uuid.Nil, [crypto.MacKeySize]byte{}, err
	}

	macSlice := []byte(result[1])
	if len(macSlice) != crypto.MacKeySize {
		return uuid.Nil, [crypto.MacKeySize]byte{}, errors.New("invalid mac tag")
	}
	var macTag [crypto.MacKeySize]byte
	copy(macTag[:], macSlice)

	return parsedUUID, macTag, nil
}
