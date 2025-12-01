/*
 * Vayen Auth (Vayen_Auth.main): GeneralData.kt
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

package dev.vayen.other

import com.mayakapps.kache.ObjectKache
import dev.vayen.config.Config
import dev.vayen.data.Account
import dev.vayen.data.Session
import org.jetbrains.exposed.sql.Database
import java.util.*

data class GeneralData<K : Any, V : Any>(
    val config: Config,
    val database: Database,
    val cache: ObjectKache<K, V>,
)

class AccountServiceData(
    val generalData: GeneralData<UUID, Account>,
    val account: Account
)

class SessionServiceData(
    val sessionData: GeneralData<UUID, Session>,
    val session: Session,
    val uuid: UUID,
    val macTag: ByteArray
)
