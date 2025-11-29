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
	"auth/config"
	"auth/data"
	"auth/service"
	"context"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

type contextKey string

const (
	ConfigKey = contextKey("config")
	LoggerKey = contextKey("logger")

	SessionServiceSetupKey = contextKey("session_service_setup")
	AccountServiceSetupKey = contextKey("account_service_setup")
	MFAServiceSetupKey     = contextKey("mfa_service_setup")

	UUIDKey    = contextKey("session_uuid")
	MacTagKey  = contextKey("session_mac_tag")
	SessionKey = contextKey("session")
	AccountKey = contextKey("account")
)

type GeneralContext struct {
	Config config.Config
	Logger *zerolog.Logger
}

type SessionContext struct {
	ServiceSetup service.GeneralData[data.Session]
	Session      data.Session
	UUID         uuid.UUID
	MacTag       []byte
}

type AccountContext struct {
	ServiceSetup service.GeneralData[data.Account]
	Account      data.Account
}

type TOTPContext struct {
	ServiceSetup service.GeneralData[data.MFAMethod]
}

func GetKeysFromContext(context context.Context) (GeneralContext, SessionContext, AccountContext, TOTPContext) {
	retrievedConfig := context.Value(ConfigKey).(config.Config)
	retrievedLogger := context.Value(LoggerKey).(*zerolog.Logger)

	retrievedSessionUUID := context.Value(UUIDKey).(uuid.UUID)
	retrievedSessionMacTag := context.Value(MacTagKey).([]byte)

	retrievedSessionServiceSetup := context.Value(SessionServiceSetupKey).(service.GeneralData[data.Session])
	retrievedSession := context.Value(SessionKey).(data.Session)

	retrievedAccountServiceSetup := context.Value(AccountServiceSetupKey).(service.GeneralData[data.Account])
	retrievedAccount := context.Value(AccountKey).(data.Account)

	retrievedMFAServiceSetup := context.Value(MFAServiceSetupKey).(service.GeneralData[data.MFAMethod])

	return GeneralContext{
			Config: retrievedConfig,
			Logger: retrievedLogger,
		}, SessionContext{
			ServiceSetup: retrievedSessionServiceSetup,
			Session:      retrievedSession,
			UUID:         retrievedSessionUUID,
			MacTag:       retrievedSessionMacTag,
		}, AccountContext{
			ServiceSetup: retrievedAccountServiceSetup,
			Account:      retrievedAccount,
		}, TOTPContext{
			ServiceSetup: retrievedMFAServiceSetup,
		}
}
