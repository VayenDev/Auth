/*
 * Vayen Auth (Vayen_Auth.main): MFAWebAuthn.kt
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

package dev.vayen.data.mfa

import dev.vayen.table.mfa.MFA_WEBAUTHN_TABLE_NAME
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient
import mtctx.utilities.serialization.serializer.UUIDSerializer
import java.util.*

@Serializable
class MFAWebAuthn(
    @Transient
    override val uuid: UUID? = null,
    @Serializable(with = UUIDSerializer::class) override val userUUID: UUID,
    val credentialId: ByteArray,
    val publicKey: ByteArray,
    val attestationType: String,
    val signCount: Long,
) : MFAMethod {
    override val tableName: String = MFA_WEBAUTHN_TABLE_NAME

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as MFAWebAuthn

        if (signCount != other.signCount) return false
        if (uuid != other.uuid) return false
        if (userUUID != other.userUUID) return false
        if (!credentialId.contentEquals(other.credentialId)) return false
        if (!publicKey.contentEquals(other.publicKey)) return false
        if (attestationType != other.attestationType) return false

        return true
    }

    override fun hashCode(): Int {
        var result = signCount.hashCode()
        result = 31 * result + (uuid?.hashCode() ?: 0)
        result = 31 * result + userUUID.hashCode()
        result = 31 * result + credentialId.contentHashCode()
        result = 31 * result + publicKey.contentHashCode()
        result = 31 * result + attestationType.hashCode()
        return result
    }
}