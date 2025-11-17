/*
 * Auth: context.go
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
	"src/data"
	"src/files"
	"src/service"

	"github.com/google/uuid"
)

type contextKey string

const (
	ConfigKey              = contextKey("config")
	SessionServiceSetupKey = contextKey("session_service_setup")
	AccountServiceSetupKey = contextKey("account_service_setup")

	UUIDKey    = contextKey("session_uuid")
	MacTagKey  = contextKey("session_mac_tag")
	SessionKey = contextKey("session")
	AccountKey = contextKey("account")
)

type GeneralContext struct {
	Config files.Config
}

type SessionContext struct {
	ServiceSetup service.SessionServiceSetup
	Session      data.Session
	UUID         uuid.UUID
	MacTag       []byte
}

type AccountContext struct {
	ServiceSetup service.AccountServiceSetup
	Account      data.Account
}

func GetKeysFromContext(context context.Context) (GeneralContext, SessionContext, AccountContext) {
	retrievedConfig := context.Value(ConfigKey).(files.Config)
	retrievedSessionUUID := context.Value(UUIDKey).(uuid.UUID)
	retrievedSessionMacTag := context.Value(MacTagKey).([]byte)

	retrievedSessionServiceSetup := context.Value(SessionServiceSetupKey).(service.SessionServiceSetup)
	retrievedSession := context.Value(SessionKey).(data.Session)

	retrievedAccountServiceSetup := context.Value(AccountServiceSetupKey).(service.AccountServiceSetup)
	retrievedAccount := context.Value(AccountKey).(data.Account)

	return GeneralContext{
			Config: retrievedConfig,
		}, SessionContext{
			ServiceSetup: retrievedSessionServiceSetup,
			Session:      retrievedSession,
			UUID:         retrievedSessionUUID,
			MacTag:       retrievedSessionMacTag,
		}, AccountContext{
			ServiceSetup: retrievedAccountServiceSetup,
			Account:      retrievedAccount,
		}
}
