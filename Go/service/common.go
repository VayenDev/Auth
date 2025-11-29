/*
 * Auth: common.go
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

package service

import (
	"auth/config"
	"context"
	"errors"

	"github.com/dgraph-io/ristretto/v2"
	"github.com/jackc/pgx/v5/pgxpool"
)

type GeneralData[T any] struct {
	Config    config.Config
	Database  *pgxpool.Pool
	DBContext context.Context
	Cache     *ristretto.Cache[[]byte, T]
}

func (setup GeneralData[T]) Validate() error {
	if setup.Database == nil {
		return errors.New("database is required")
	}
	if setup.Cache == nil {
		return errors.New("cache is required")
	}
	return nil
}
