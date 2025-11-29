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
