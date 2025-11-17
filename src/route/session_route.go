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
	"encoding/base64"
	"fmt"
	"net/http"
	"src/crypto"
	"src/service"
	"time"

	"github.com/rs/zerolog/log"
)

func HandleSessionValid(writer http.ResponseWriter, request *http.Request) {
	_, sessionContext, _ := GetKeysFromContext(request.Context())

	isValid := crypto.VerifyMAC([]byte(fmt.Sprintf("%s:%d", sessionContext.UUID, sessionContext.Session.ValidFor)), sessionContext.MacTag[:], sessionContext.Session.MacKey[:])

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
	_, sessionContext, _ := GetKeysFromContext(request.Context())
	expired := sessionContext.Session.Expired()

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
	_, sessionContext, _ := GetKeysFromContext(request.Context())
	err := service.DeleteSession(sessionContext.ServiceSetup, sessionContext.UUID)
	if err != nil {
		http.Error(writer, "Failed to delete session", http.StatusInternalServerError)
		log.Err(err)
		return
	}
}

func BuildSessionHttpCookie(token string, validFor time.Duration) *http.Cookie {
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
		Name:     "session",
		Value:    base64.URLEncoding.EncodeToString([]byte(token)),
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   maxAge,
		Expires:  expires,
	}
}

func ReadSessionHttpCookie(request *http.Request) (string, error) {
	cookie, err := request.Cookie("session")
	if err != nil {
		return "", err
	}

	decoded, err := base64.URLEncoding.DecodeString(cookie.Value)
	if err != nil {
		return "", err
	}

	return string(decoded), nil
}
