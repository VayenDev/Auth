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
	"context"
	"fmt"
	"net/http"
	"src/crypto"
	"src/data"
	"src/files"
	"src/service"
	"strings"

	"github.com/rs/zerolog/log"
)

func HandleSessionValid(writer http.ResponseWriter, request *http.Request) {
	_, _, _, session, _ := GetKeysFromContext(request.Context())

	_, macTag, err := service.SplitUUIDAndMAC(request.Header.Get("Authorization"))
	if err != nil {
		http.Error(writer, "Invalid authorization header", http.StatusUnauthorized)
		log.Err(err)
		return
	}

	isValid := crypto.VerifyMAC([]byte(fmt.Sprintf("%s:%d", session.UUID, session.ValidFor)), macTag[:], session.MacKey[:])

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
	_, _, _, session, _ := GetKeysFromContext(request.Context())
	expired := session.Expired()

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
	_, sss, _, session, _ := GetKeysFromContext(request.Context())
	err := service.DeleteSession(sss, session.UUID)
	if err != nil {
		http.Error(writer, "Failed to delete session", http.StatusInternalServerError)
		log.Err(err)
		return
	}
}

func SessionMiddleware(config files.Config, sessionServiceSetup service.SessionServiceSetup, accountServiceSetup service.AccountServiceSetup, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		ctx = context.WithValue(ctx, ConfigKey, config)
		ctx = context.WithValue(ctx, SessionServiceSetupKey, sessionServiceSetup)
		ctx = context.WithValue(ctx, AccountServiceSetupKey, accountServiceSetup)

		authHeader := r.Header.Get("Authorization")
		if strings.TrimSpace(authHeader) == "" || !strings.HasPrefix(authHeader, "VA:") {
			http.Error(w, "Authorization header is required", http.StatusUnauthorized)
			return
		}

		if r.URL.Path == "/account/login" || r.URL.Path == "/account/register" {
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		retrievedUUID, _, err := service.SplitUUIDAndMAC(authHeader)
		if err != nil {
			http.Error(w, "Invalid authorization header", http.StatusUnauthorized)
			log.Err(err)
			return
		}

		session, err := service.GetSession(sessionServiceSetup, retrievedUUID)
		if err != nil {
			http.Error(w, "Invalid authorization header", http.StatusUnauthorized)
			log.Err(err)
			return
		}

		ctx = context.WithValue(ctx, SessionKey, session)

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

		ctx = context.WithValue(ctx, AccountKey, account)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}

func GetKeysFromContext(context context.Context) (files.Config, service.SessionServiceSetup, service.AccountServiceSetup, data.Session, data.Account) {
	retrievedConfig := context.Value(ConfigKey).(files.Config)
	retrievedSessionServiceSetup := context.Value(SessionServiceSetupKey).(service.SessionServiceSetup)
	retrievedAccountServiceSetup := context.Value(AccountServiceSetupKey).(service.AccountServiceSetup)

	retrievedSession := context.Value(SessionKey).(data.Session)
	retrievedAccount := context.Value(AccountKey).(data.Account)

	return retrievedConfig, retrievedSessionServiceSetup, retrievedAccountServiceSetup, retrievedSession, retrievedAccount
}
