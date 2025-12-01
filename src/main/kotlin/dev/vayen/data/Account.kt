/*
 * Vayen Auth (Vayen_Auth.main): Account.kt
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

package dev.vayen.data

import java.util.*

class Account(
    val uuid: UUID,
    val username: String,
    val passwordHash: ByteArray,
    val webhookUUID: UUID,
    val recoveryCodes: List<String> // max. 5
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as Account

        if (uuid != other.uuid) return false
        if (username != other.username) return false
        if (!passwordHash.contentEquals(other.passwordHash)) return false
        if (webhookUUID != other.webhookUUID) return false
        if (recoveryCodes != other.recoveryCodes) return false

        return true
    }

    override fun hashCode(): Int {
        var result = uuid.hashCode()
        result = 31 * result + username.hashCode()
        result = 31 * result + passwordHash.contentHashCode()
        result = 31 * result + webhookUUID.hashCode()
        result = 31 * result + recoveryCodes.hashCode()
        return result
    }
}
