/*
 * Auth: rate_limiter.go
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
	"net"
	"net/http"
	"src/files"
	"src/service"

	"github.com/dgraph-io/ristretto/v2"
	"golang.org/x/time/rate"
)

func RateLimitMiddleware(rateLimitCache *ristretto.Cache[[]byte, *rate.Limiter], config *files.Config, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := GetIdentifier(r)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
		}

		rateLimiter, success := rateLimitCache.Get(id)
		if !success {
			http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
		}

		if rateLimiter == nil {
			rateLimiter = rate.NewLimiter(rate.Every(config.RateLimit.Window), config.RateLimit.MaxRequests)
			rateLimitCache.Set(id, rateLimiter, 0)
		}

		if !rateLimiter.Allow() {
			http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func GetIdentifier(r *http.Request) ([]byte, error) {
	sessionCookie, err := GetSessionCookie(nil, r)
	if err == nil {
		retrievedUUID, _, err := service.SplitUUIDAndMAC(sessionCookie)
		if err != nil {
			ip, err := GetIp(r)
			if err != nil {
				return nil, err
			}
			return []byte(ip), nil
		}

		return retrievedUUID[:], nil
	}

	ip, err := GetIp(r)
	if err != nil {
		return nil, err
	}
	return []byte(ip), nil
}

func GetIp(r *http.Request) (string, error) {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return "", err
	}
	return ip, nil
}
