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
