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
	"fmt"
	"net/http"
	"src/service"
	"strings"

	"github.com/rs/zerolog/log"
)

func HandleAccountRegister(writer http.ResponseWriter, request *http.Request) {
	query := request.URL.Query()
	username := strings.TrimSpace(query.Get("username"))
	password := strings.TrimSpace(query.Get("password"))

	if username == "" || password == "" {
		http.Error(writer, "Username and password are required", http.StatusBadRequest)
		return
	}

	ass := request.Context().Value(AccountServiceSetupKey).(service.AccountServiceSetup)
	_, err := service.CreateAccount(ass, username, password)
	if err != nil {
		http.Error(writer, "Failed to create account", http.StatusInternalServerError)
		log.Err(err)
		return
	}

	writer.WriteHeader(http.StatusOK)
}
func HandleAccountLogin(writer http.ResponseWriter, request *http.Request) {
	query := request.URL.Query()
	username := strings.TrimSpace(query.Get("username"))
	password := strings.TrimSpace(query.Get("password"))

	if username == "" || password == "" {
		http.Error(writer, "Username and password are required", http.StatusBadRequest)
		return
	}

	config, sss, _, _, _ := GetKeysFromContext(request.Context())
	ass := request.Context().Value(AccountServiceSetupKey).(service.AccountServiceSetup)

	sessionFormatted, err := service.AccountLogin(ass, sss, config.Session.ValidFor, username, password)
	if err != nil {
		http.Error(writer, "Failed to login", http.StatusInternalServerError)
		log.Err(err)
		return
	}

	writer.WriteHeader(http.StatusOK)
	_, err = fmt.Fprintf(writer, sessionFormatted)
	if err != nil {
		http.Error(writer, "Failed to write session", http.StatusInternalServerError)
		log.Err(err)
		return
	}
}
func HandleChangePassword(writer http.ResponseWriter, request *http.Request) {
	query := request.URL.Query()
	newPassword := strings.TrimSpace(query.Get("newPassword"))

	if strings.TrimSpace(newPassword) == "" {
		http.Error(writer, "New password is required", http.StatusBadRequest)
		return
	}

	_, _, ass, _, account := GetKeysFromContext(request.Context())

	err := service.UpdatePassword(ass, account.UUID, newPassword)
	if err != nil {
		http.Error(writer, "Failed to update password", http.StatusInternalServerError)
		log.Err(err)
		return
	}

	writer.WriteHeader(http.StatusOK)
	return
}

func HandleAccountDelete(writer http.ResponseWriter, request *http.Request) {
	_, _, ass, _, account := GetKeysFromContext(request.Context())
	err := service.DeleteAccount(ass, account.UUID)
	if err != nil {
		http.Error(writer, "Failed to delete session", http.StatusInternalServerError)
		log.Err(err)
		return
	}
}
