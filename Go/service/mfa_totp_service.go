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
