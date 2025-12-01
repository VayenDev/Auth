/*
 * Vayen Auth (Vayen_Auth.main): Plugin.kt
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

package dev.vayen

import dev.vayen.config.Config
import dev.vayen.data.CSRFSession
import dev.vayen.data.Session
import dev.vayen.middleware.SAPMiddleware
import dev.vayen.service.AccountService
import dev.vayen.service.SessionService
import io.github.flaxoos.ktor.server.plugins.ratelimiter.RateLimiting
import io.github.flaxoos.ktor.server.plugins.ratelimiter.implementations.TokenBucket
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.plugins.callid.*
import io.ktor.server.plugins.calllogging.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.plugins.cors.routing.*
import io.ktor.server.plugins.csrf.*
import io.ktor.server.plugins.forwardedheaders.*
import io.ktor.server.plugins.hsts.*
import io.ktor.server.plugins.httpsredirect.*
import io.ktor.server.request.*
import io.ktor.server.resources.*
import io.ktor.server.response.*
import io.ktor.server.sessions.*
import kotlinx.serialization.json.Json
import mtctx.lumina.v4.Lumina
import mtctx.utilities.serialization.jsonForMachines
import org.slf4j.event.Level
import java.util.*

fun Application.setupPlugins(
    config: Config,
    lumina: Lumina,
    accountService: AccountService,
    sessionService: SessionService
) {
    install(XForwardedHeaders)

    if (config.tls.enabled) {
        if (config.tls.hsts.enabled)
            install(HSTS) {
                includeSubDomains = config.tls.hsts.includeSubdomains
                preload = config.tls.hsts.preload
                maxAgeInSeconds = config.tls.hsts.maxAgeInSeconds.inWholeSeconds

                customDirectives.putAll(config.tls.hsts.customDirectives)
            }

        install(HttpsRedirect) {
            sslPort = config.tls.port
            permanentRedirect = config.tls.httpsRedirect.permanentRedirect

            config.tls.httpsRedirect.excludedPrefixes.forEach(::excludePrefix)
            config.tls.httpsRedirect.excludedSuffixes.forEach(::excludeSuffix)
        }
    }

    install(CallId) {
        header(HttpHeaders.XRequestId)
        verify { callId: String -> callId.isNotEmpty() }
        generate { UUID.randomUUID().toString() }
    }

    install(CallLogging) {
        callIdMdc("call-id")
        level = Level.INFO
        filter { call -> (call.response.status()?.value ?: 0) >= 400 }
        format { call ->
            val id = call.callId ?: "no-call-id"
            "call-id=$id, method=${call.request.httpMethod.value}, path=${call.request.path()}, status=${call.response.status()}"
        }
    }

    install(ContentNegotiation) {
        Json(jsonForMachines) {
            ignoreUnknownKeys = true
        }
    }

    install(Resources)

    if (config.rateLimit.enabled)
        install(RateLimiting) {
            rateLimiter {
                type = TokenBucket::class
                capacity = config.rateLimit.maxRequests
                rate = config.rateLimit.window
            }
        }

    install(CORS) {
        config.cors.allowedHeaders.forEach(::allowHeader)
        config.cors.allowedHeadersPrefixed.forEach(::allowHeadersPrefixed)
        config.cors.allowedMethods.forEach(::allowMethod)
        config.cors.allowedOrigins.apply {
            if (contains("*")) anyHost()
            else forEach(::allowHeader)
        }
    }

    install(Sessions) {
        cookie<Session>("vayen_session") {
            cookie.path = "/"
            cookie.httpOnly = true
            cookie.secure = config.tls.enabled
            cookie.sameSite = SameSite.Strict
            cookie.maxAge = config.session.validFor
            serializer = Session.Serializer(sessionService)
        }

        if (config.csrf.enabled)
            cookie<CSRFSession>("vayen_csrf") {
                cookie.path = "/"
                cookie.httpOnly = false
                cookie.secure = config.tls.enabled
                cookie.sameSite = SameSite.Strict
            }
    }

    if (config.csrf.enabled)
        install(CSRF) {
            config.csrf.allowedOrigins.forEach(::allowOrigin)

            if (config.csrf.originMatchesHost) originMatchesHost()

            config.csrf.headerChecks.forEach {
                checkHeader(it) { headerValue ->
                    val csrfSession = sessions.get<CSRFSession>() ?: return@checkHeader false

                    val valid = headerValue == csrfSession.csrfToken
                    if (valid) sessions.set(CSRFSession())
                    valid
                }
            }

            if (config.csrf.failWithBadRequest) onFailure { reason ->
                lumina.error {
                    line("CSRF validation failed")
                    line("Reason: $reason")
                    line("Call ID: $callId")
                }
                respond(HttpStatusCode.BadRequest, "Cross-site request validation failed")
            }
        }

    install(SAPMiddleware) {
        this.config = config
        this.lumina = lumina
        this.accountService = accountService
        this.sessionService = sessionService
    }
}