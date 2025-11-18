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
	"errors"
	"fmt"
	"src/crypto"
	"src/data"
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
