/*
 * Vayen Auth (Vayen_Auth.main): ConfigDefaults.kt
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

package dev.vayen.config

import dev.vayen.config.authentication.AccountConfig
import dev.vayen.config.authentication.SessionConfig
import dev.vayen.config.security.*
import dev.vayen.config.storage.CacheConfig
import dev.vayen.config.storage.DatabaseConfig
import io.ktor.http.*
import mtctx.utilities.datasizes.mib
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

object ConfigDefaults {
    val database = DatabaseConfig(
        "localhost",
        3306,
        "<change this to your database name>",
        "<change this to your database username>",
        "<change this to your database password>",
        10
    )
    val session = SessionConfig(
        15.minutes
    )
    val hsts = HSTSConfig(
        enabled = true,
        includeSubdomains = true,
        preload = true,
        maxAgeInSeconds = 365.days,
        customDirectives = mapOf()
    )

    val httpsRedirect = HttpsRedirectConfig(
        true,
        listOf("/health", "/healthz", "/ready", "/live", "/metrics", "/actuator", "/internal", "/ws", "/websocket"),
        listOf()
    )
    val tls = TLSConfig(
        false,
        443,
        hsts,
        httpsRedirect
    )

    val cors = CORSConfig(
        listOf("localhost"),
        listOf(
            HttpMethod.Get,
            HttpMethod.Post,
            HttpMethod.Delete
        ),
        listOf("Cookie"),
        listOf()
    )

    val csrf = CSRFConfig(
        true,
        originMatchesHost = true,
        allowedOrigins = listOf(),
        headerChecks = listOf("X-CSRF-Token", "_csrf"),
        failWithBadRequest = true
    )

    val rateLimit = RateLimitConfig(
        enabled = true,
        window = 5.seconds,
        maxRequests = 10
    )

    val cache = CacheConfig(
        128.mib,
        64.mib,
    )

    val account = AccountConfig(
        AccountConfig.UsernamePolicyConfig(
            listOf('!', '@', '#', '$', '%', '^', '&', '*', '(', ')'),
            DefaultBannedWords,
            5,
            20
        ),
        AccountConfig.PasswordPolicyConfig(
            10,
            128,
            2,
            2,
            2,
            1,
            listOf('!', '@', '#', '$', '%', '^', '&', '*', '(', ')')
        )
    )

    val mfa_totp = TOTPConfig(
        "Vayen Auth",
        200,
        200
    )
    val mfa_webauthn = WebAuthnConfig(
        "Vayen Auth",
        "https://vayen.dev/auth",
        listOf("https://vayen.dev/auth")
    )
    val mfa = MFAConfig(
        mfa_totp,
        mfa_webauthn
    )

    val port = 8080
}