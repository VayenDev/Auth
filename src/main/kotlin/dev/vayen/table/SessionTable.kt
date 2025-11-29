/*
 * Vayen Auth (Vayen_Auth.main): SessionTable.kt
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

package dev.vayen.table

import org.jetbrains.exposed.sql.ReferenceOption
import org.jetbrains.exposed.sql.Table
import org.jetbrains.exposed.sql.kotlin.datetime.duration
import org.jetbrains.exposed.sql.kotlin.datetime.timestamp
import kotlin.uuid.ExperimentalUuidApi

@OptIn(ExperimentalUuidApi::class)
object SessionTable : Table("sessions") {
    val uuid = uuid("uuid")
    val userUUID = reference("user_uuid", AccountTable.uuid, ReferenceOption.CASCADE)
    val macKey = binary("mac_key", 32)
    val createdAt = timestamp("created_at")
    val validFor = duration("valid_for")

    override val primaryKey = PrimaryKey(uuid)

    init {
        index("idx_sessions_user", false, userUUID)
    }
}
