/*
 * Auth: session_and_account_parsing.go
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

package middleware

import (
	"context"
	"net/http"
	"src/data"
	"src/files"
	"src/route"
	"src/service"
	"strings"

	"github.com/rs/zerolog/log"
)

func SessionAndAccountParsingMiddleware(config files.Config, sessionServiceSetup service.GeneralData[data.Session], accountServiceSetup service.GeneralData[data.Account], next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		ctx = context.WithValue(ctx, route.ConfigKey, config)
		ctx = context.WithValue(ctx, route.SessionServiceSetupKey, sessionServiceSetup)
		ctx = context.WithValue(ctx, route.AccountServiceSetupKey, accountServiceSetup)

		sessionCookie, _ := GetSessionCookie(w, r)

		if r.URL.Path == "/account/login" || r.URL.Path == "/account/register" {
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		sessionCookie, err := GetSessionCookie(w, r)
		if err != nil {
			return
		}

		retrievedUUID, macTag, err := service.SplitUUIDAndMAC(sessionCookie)
		if err != nil {
			http.Error(w, "Invalid authorization header", http.StatusUnauthorized)
			log.Err(err)
			return
		}
		ctx = context.WithValue(ctx, route.UUIDKey, retrievedUUID)
		ctx = context.WithValue(ctx, route.MacTagKey, macTag)

		session, err := service.GetSession(sessionServiceSetup, retrievedUUID)
		if err != nil {
			http.Error(w, "Invalid authorization header", http.StatusUnauthorized)
			log.Err(err)
			return
		}

		ctx = context.WithValue(ctx, route.SessionKey, session)

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

		ctx = context.WithValue(ctx, route.AccountKey, account)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}

func GetSessionCookie(w http.ResponseWriter, r *http.Request) (string, error) {
	sessionCookie, err := route.ReadSessionHttpCookie(r)
	if err != nil {
		if w != nil {
			http.Error(w, "Failed to read session cookie", http.StatusInternalServerError)
			log.Err(err)
		}
		return "", err
	}

	if strings.TrimSpace(sessionCookie) == "" || !strings.HasPrefix(sessionCookie, "VA:") {
		if w != nil {
			http.Error(w, "Authorization header is required", http.StatusUnauthorized)
		}
		return "", err
	}

	return sessionCookie, nil
}
