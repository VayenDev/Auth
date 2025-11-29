/*
 * Auth: webauthn_user.go
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

package data

import (
	"github.com/go-webauthn/webauthn/webauthn"
)

type WebAuthnUser struct {
	Account     *Account
	Credentials []webauthn.Credential
}

func (user *WebAuthnUser) WebAuthnID() []byte {
	binary, _ := user.Account.UUID.MarshalBinary()
	return binary
}

func (user *WebAuthnUser) WebAuthnName() string {
	return user.Account.Username
}

func (user *WebAuthnUser) WebAuthnDisplayName() string {
	return user.Account.Username
}

func (user *WebAuthnUser) WebAuthnIcon() string {
	return ""
}

func (user *WebAuthnUser) WebAuthnCredentials() []webauthn.Credential {
	return user.Credentials
}
