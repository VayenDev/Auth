/*
 * Vayen Auth (Vayen_Auth.main): MFATOTPTable.kt
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

const val MFA_TOTP_TABLE_NAME = "mfa_totp"

object MFATOTPTable : Table(MFA_TOTP_TABLE_NAME) {
    val uuid = uuid("uuid").index()
    val userUUID = reference("user_uuid", AccountTable.uuid, ReferenceOption.CASCADE).index()
    val secret = text("secret")

    override val primaryKey = PrimaryKey(uuid)
}