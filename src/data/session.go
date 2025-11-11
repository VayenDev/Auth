/*
 * Auth: session.go
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
	"src/crypto"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func CreateSessionTable(conn *pgx.Conn) error {
	const schema = `
        CREATE TABLE IF NOT EXISTS sessions (
            uuid UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            user_uuid UUID NOT NULL,
            mac_key BYTEA NOT NULL,
            created_at BIGINT NOT NULL,
            valid_for BIGINT NOT NULL,
            created_at_expires TIMESTAMPTZ NOT NULL GENERATED ALWAYS AS (
                to_timestamp(created_at::double precision / 1000000000) + 
                (valid_for::text || ' seconds')::interval
            ) STORED,
            CONSTRAINT fk_user 
                FOREIGN KEY (user_uuid) REFERENCES accounts(uuid) 
                ON DELETE CASCADE
        );
        
        CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(created_at_expires);
        CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_uuid);
    `

	_, err := conn.Exec(context.Background(), schema)
	return err
}

var SessionCost = int64(32 + crypto.MacKeySize + 8 + 8)

type Session struct {
	UserUUID  uuid.UUID
	UUID      uuid.UUID
	MacKey    [crypto.MacKeySize]byte // HMAC SHA 256
	CreatedAt int64
	ValidFor  time.Duration
}

func (session Session) Expired() bool {
	return time.Now().UnixNano()-session.CreatedAt > int64(session.ValidFor)
}
