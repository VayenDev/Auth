/*
 * Auth: hmac.go
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

package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
)

const MacKeySize = 32

func NewMACKey() ([]byte, error) {
	key := make([]byte, MacKeySize)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func ComputeMAC(input, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(input)
	return mac.Sum(nil)
}

func VerifyMAC(input, hash, key []byte) bool {
	return hmac.Equal(hash, ComputeMAC(input, key))
}
