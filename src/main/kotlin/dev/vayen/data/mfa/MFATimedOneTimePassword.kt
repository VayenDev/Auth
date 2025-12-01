/*
 * Vayen Auth (Vayen_Auth.main): MFATimedOneTimePassword.kt
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

package dev.vayen.data.mfa

import dev.vayen.config.UUIDSerializer
import dev.vayen.table.mfa.MFA_TOTP_TABLE_NAME
import kotlinx.serialization.Serializable
import java.util.*

@Serializable
data class MFATimedOneTimePassword(
    @Serializable(with = UUIDSerializer::class) override val uuid: UUID,
    @Serializable(with = UUIDSerializer::class) override val userUUID: UUID,
    val secret: String
) : MFAMethod {
    override val tableName: String = MFA_TOTP_TABLE_NAME
}