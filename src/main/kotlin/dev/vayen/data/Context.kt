/*
 * Vayen Auth (Vayen_Auth.main): Context.kt
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

import dev.vayen.config.Config
import dev.vayen.service.AccountService
import dev.vayen.service.SessionService
import io.ktor.server.routing.*
import io.ktor.util.*
import mtctx.lumina.v4.Lumina

object ContextKey {
    val Config = AttributeKey<Config>("config")
    val Lumina = AttributeKey<Lumina>("lumina")

    val Route.config: Config get() = attributes[Config]
    val Route.lumina: Lumina get() = attributes[Lumina]

    object Service {
        val Account = AttributeKey<AccountService>("account")
        val Session = AttributeKey<SessionService>("session")

        val Route.accountService: AccountService get() = attributes[Account]
        val Route.sessionService: SessionService get() = attributes[Session]
    }

    object Data {
        val Account = AttributeKey<Account>("account")

        val Route.currentAccount: Account get() = attributes[Account]
    }
}