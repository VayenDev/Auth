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
