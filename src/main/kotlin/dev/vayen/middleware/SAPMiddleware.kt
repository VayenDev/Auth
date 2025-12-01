/*
 * Vayen Auth (Vayen_Auth.main): SAPMiddleware.kt
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

package dev.vayen.middleware

import dev.vayen.config.Config
import dev.vayen.data.ContextKey
import dev.vayen.data.Session
import dev.vayen.route.Body
import dev.vayen.service.AccountService
import dev.vayen.service.SessionService
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.sessions.*
import io.ktor.utils.io.*
import mtctx.lumina.v4.Lumina

// Session and Account Parsing Middleware
val SAPMiddleware = createApplicationPlugin("session_and_account_parsing", createConfiguration = ::SAPConfig) {
    val config = pluginConfig.config ?: error("The config for SAP must be set")
    val lumina = pluginConfig.lumina ?: error("The lumina instance must be set")
    val accountService = pluginConfig.accountService ?: error("The account cache must be set")
    val sessionService = pluginConfig.sessionService ?: error("The session cache must be set")

    val whitelistedRoutes = setOf(
        "/account/register",
        "/account/login"
    )

    onCall { call ->
        call.attributes.put(ContextKey.Config, config)
        call.attributes.put(ContextKey.Lumina, lumina)
        call.attributes.put(ContextKey.Service.Account, accountService)
        call.attributes.put(ContextKey.Service.Session, sessionService)

        val requestPath = call.request.path()
        if (requestPath in whitelistedRoutes) return@onCall

        val currentSession = call.sessions.get<Session>()
        if (currentSession == null) {
            call.respond(HttpStatusCode.Unauthorized)
            return@onCall
        }

        if (requestPath == "/session/valid") return@onCall

        if (currentSession.expired()) {
            call.sessions.clear<Session>()
            sessionService.delete(currentSession.uuid)
            call.respond<Body.ErrorResponse>(
                HttpStatusCode.Unauthorized,
                Body.ErrorResponse("Session is expired and will be invalidated now!")
            )
            return@onCall
        }

        val retrievedAccount = accountService.getBySession(currentSession.uuid).getOrNull() ?: run {
            call.respond<Body.ErrorResponse>(
                HttpStatusCode.Unauthorized,
                Body.ErrorResponse("Could not retrieve account from session, try again later or clear your cookies and log in again!")
            )
            return@onCall
        }
        call.attributes.put(ContextKey.Data.Account, retrievedAccount)
    }
}

@KtorDsl
class SAPConfig {
    internal var config: Config? = null
    internal var lumina: Lumina? = null
    internal var accountService: AccountService? = null
    internal var sessionService: SessionService? = null
}