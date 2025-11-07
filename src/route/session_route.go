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

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

const (
	ConfigKey              = contextKey("files")
	SessionServiceSetupKey = contextKey("session_service_setup")

	UUIDKey    = contextKey("uuid")
	MacTagKey  = contextKey("mac_tag")
	SessionKey = contextKey("session")
)

func HandleSessionCreate(writer http.ResponseWriter, request *http.Request) {
	config, sss := request.Context().Value(ConfigKey).(files.Config), request.Context().Value(SessionServiceSetupKey).(service.SessionServiceSetup)
	session, mac, err := service.CreateSession(sss, config.Session.ValidFor)
	if err != nil {
		http.Error(writer, "Failed to create session", http.StatusInternalServerError)
		log.Err(err)
		return
	}

	writer.WriteHeader(http.StatusOK)
	if _, err = fmt.Fprintf(writer, "VA:%s.%s", session.UUID, mac); err != nil {
		log.Err(err)
		return
	}
}
func HandleSessionValid(writer http.ResponseWriter, request *http.Request) {
	_, _, retrievedUUID, macTag, session := GetKeysFromContext(request.Context())

	isValid := crypto.VerifyMAC([]byte(fmt.Sprintf("%s:%d", retrievedUUID, session.ValidFor)), []byte(macTag), session.MacKey[:])

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
	_, _, _, _, session := GetKeysFromContext(request.Context())
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
	_, sss, retrievedUUID, _, _ := GetKeysFromContext(request.Context())
	err := service.DeleteSession(sss, retrievedUUID)
	if err != nil {
		http.Error(writer, "Failed to delete session", http.StatusInternalServerError)
		log.Err(err)
		return
	}
}

func SessionMiddleware(config files.Config, sessionServiceSetup service.SessionServiceSetup, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		ctx = context.WithValue(ctx, ConfigKey, config)
		ctx = context.WithValue(ctx, SessionServiceSetupKey, sessionServiceSetup)

		if r.URL.Path == "/session/create" {
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		authHeader := r.Header.Get("Authorization")
		if strings.TrimSpace(authHeader) == "" || !strings.HasPrefix(authHeader, "VA:") {
			http.Error(w, "Authorization header is required", http.StatusUnauthorized)
			return
		}

		retrievedUUID, macTag, err := service.SplitUUIDAndMAC(authHeader)
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

		ctx = context.WithValue(ctx, UUIDKey, retrievedUUID)
		ctx = context.WithValue(ctx, MacTagKey, macTag)
		ctx = context.WithValue(ctx, SessionKey, session)

		r = r.WithContext(ctx)

		if r.URL.Path == "/session/valid" {
			next.ServeHTTP(w, r)
			return
		}

		if session.Expired() {
			http.Error(w, "Session expired", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func GetKeysFromContext(context context.Context) (files.Config, service.SessionServiceSetup, uuid.UUID, string, data.Session) {
	retrievedConfig := context.Value(ConfigKey).(files.Config)
	retrievedSessionServiceSetup := context.Value(SessionServiceSetupKey).(service.SessionServiceSetup)

	retrievedUUID := context.Value(UUIDKey).(uuid.UUID)
	retrievedMacTag := context.Value(MacTagKey).(string)
	retrievedSession := context.Value(SessionKey).(data.Session)

	return retrievedConfig, retrievedSessionServiceSetup, retrievedUUID, retrievedMacTag, retrievedSession
}
