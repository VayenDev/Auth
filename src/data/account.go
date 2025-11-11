/*
 * Auth: account.go
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
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func CreateAccountTable(conn *pgx.Conn) error {
	const schema = `
        CREATE TABLE IF NOT EXISTS accounts (
            uuid UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            username VARCHAR(32) NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            webhook_id UUID NOT NULL UNIQUE,
        );
        
        CREATE INDEX IF NOT EXISTS idx_webhook_id ON accounts(webhook_id);
    `

	_, err := conn.Exec(context.Background(), schema)
	return err
}

type Account struct {
	UUID         uuid.UUID
	Username     string
	PasswordHash string
	WebhookID    uuid.UUID // A unique webhook ID for the account. It is used to receive notifications for e.g., password reset, ... without providing an e-mail address.
}
