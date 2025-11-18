/*
 * Auth: mfa.go
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
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	TOTPTableName     = "mfa_totp"
	WebAuthnTableName = "mfa_webauthn"
)

func CreateMFATable(conn *pgx.Conn) error {
	schema := fmt.Sprintf(`
		CREATE TABLE IF NOT EXISTS %s (
			uuid UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			user_uuid UUID NOT NULL REFERENCES accounts(uuid) ON DELETE CASCADE,
			secret TEXT,
		);
		CREATE TABLE IF NOT EXISTS %s (
			uuid UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			user_uuid UUID NOT NULL REFERENCES accounts(uuid) ON DELETE CASCADE,
			
		    credential_id BYTEA NOT NULL UNIQUE,
		    public_key TEXT NOT NULL,
		    attestation_type TEXT NOT NULL
		    sign_count INTEGER NOT NULL,
		    transports TEXT[] NOT NULL,
		    
		    -- Backup/Sync Flags (Passkeys)
		    backup_eligible boolean NOT NULL,
		    backup_state TEXT NOT NULL,
		);
		
		-- Indexes
		CREATE INDEX IF NOT EXISTS idx_mfa_totp_user_uuid ON mfa_totp(user_uuid);
		CREATE INDEX IF NOT EXISTS idx_mfa_webauthn_user_uuid ON mfa_webauthn(user_uuid);

		CREATE INDEX IF NOT EXISTS idx_mfa_webauthn_credential_id ON mfa_webauthn(credential_id);
		CREATE INDEX IF NOT EXISTS idx_mfa_webauthn_user ON mfa_webauthn(user_uuid)
    `, TOTPTableName, WebAuthnTableName)

	_, err := conn.Exec(context.Background(), schema)
	return err
}

type MFAMethod interface {
	GetTableName() string
}

func GetTableName[T MFAMethod]() string {
	var mfa T
	return mfa.GetTableName()
}

type MFA struct {
	MFAMethod
	UUID     uuid.UUID `db:"uuid"`
	UserUUID uuid.UUID `db:"user_uuid"`
}

type MFATimedOneTimePassword struct {
	MFA
	Secret string `db:"secret"`
}

func (m MFATimedOneTimePassword) GetTableName() string { return TOTPTableName }

type MFAWebAuthn struct {
	MFA
	CredentialID    uuid.UUID `db:"credential_id"`
	PublicKey       string    `db:"public_key"`
	AttestationType string    `db:"attestation_type"`
	SignCount       uint32    `db:"sign_count"`
	Transports      []string  `db:"transports"`

	// Passkey Backup Flags
	BackupEligible bool `db:"backup_eligible"`
	BackupState    bool `db:"backup_state"`
}

func (m MFAWebAuthn) GetTableName() string { return WebAuthnTableName }
