/*
 * Auth: argon2.go
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
	"github.com/alexedwards/argon2id"
)

func HashArgon2id(input string) (string, error) {
	return argon2id.CreateHash(input, argon2id.DefaultParams)
}

func VerifyArgon2id(input string, hash string) (bool, error) {
	return argon2id.ComparePasswordAndHash(input, hash)
}
