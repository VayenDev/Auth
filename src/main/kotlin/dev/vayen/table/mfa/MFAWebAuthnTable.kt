/*
 * Vayen Auth (Vayen_Auth.main): MFAWebAuthnTable.kt
 * Copyright (C) 2025 mtctx
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the **GNU General Public License** as published
 * by the Free Software Foundation, either **version 3** of the License, or
 * (at your option) any later version.
 *
 * This program is distributed WITHOUT ANY WARRANTY; see the
 * GNU General Public License for more details, which you should have
 * received with this program.
 *
 * SPDX-FileCopyrightText: 2025 mtctx
 * SPDX-License-Identifier: GPL-3.0-only
 */

package dev.vayen.table.mfa

import dev.vayen.table.AccountTable
import org.jetbrains.exposed.sql.ReferenceOption
import org.jetbrains.exposed.sql.Table

const val MFA_WEBAUTHN_TABLE_NAME = "mfa_webauthn"

object MFAWebAuthnTable : Table(MFA_WEBAUTHN_TABLE_NAME) {
    val userUUID = reference("user_uuid", AccountTable.uuid, ReferenceOption.CASCADE).index()
    val credentialId = binary("credential_id", 64).index()
    val publicKey = binary("public_key", 65)
    val attestationType = varchar("attestation_type", 32)
    val signCount = long("sign_count")

    override val primaryKey = PrimaryKey(credentialId)
}