/*
 * Vayen Auth (Vayen_Auth.main): DatabaseService.kt
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

package dev.vayen.service

import com.mayakapps.kache.ObjectKache
import dev.vayen.config.Config
import kotlinx.coroutines.Dispatchers
import mtctx.lumina.v4.Lumina
import mtctx.utilities.Outcome
import org.jetbrains.exposed.sql.Database
import org.jetbrains.exposed.sql.Transaction
import org.jetbrains.exposed.sql.transactions.experimental.newSuspendedTransaction

abstract class DatabaseService<ID : Any, T : Any>(
    protected val config: Config,
    protected val lumina: Lumina,
    protected val database: Database,
    val cache: ObjectKache<ID, T>,
) {
    abstract suspend operator fun get(id: ID): Outcome<T>
    abstract suspend fun delete(id: ID): Outcome<Unit>

    suspend fun <T> dbQuery(block: suspend Transaction.() -> T): T =
        newSuspendedTransaction(Dispatchers.IO) { block() }
}