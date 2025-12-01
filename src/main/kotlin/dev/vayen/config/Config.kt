/*
 * Vayen Auth (Vayen_Auth.main): Config.kt
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
import kotlinx.serialization.Serializable
import mtctx.lumina.v4.Lumina
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.seconds

@Serializable
data class Config(
    // Server
    val port: Int,

    // Security
    val tls: TLSConfig,
    val cors: CORSConfig,
    val csrf: CSRFConfig,
    val mfa: MFAConfig,
    val rateLimit: RateLimitConfig,

    // Authentication
    val account: AccountConfig,
    val session: SessionConfig,

    // Data & Storage
    val database: DatabaseConfig,
    val cache: CacheConfig,
) {
    companion object {
        val default = Config(
            ConfigDefaults.port,

            ConfigDefaults.tls,
            ConfigDefaults.cors,
            ConfigDefaults.csrf,
            ConfigDefaults.mfa,
            ConfigDefaults.rateLimit,

            ConfigDefaults.account,
            ConfigDefaults.session,

            ConfigDefaults.database,
            ConfigDefaults.cache
        )
    }

    suspend fun validate(lumina: Lumina): Set<String> {
        val errorList = mutableSetOf<String>()

        // ====================== Server ======================
        if (port !in 1..65535) {
            errorList.add("port must be between 1 and 65535")
        }

        // ====================== TLS ======================
        if (!tls.enabled) {
            lumina.warn(
                "TLS IS DISABLED – All connections will be sent in plaintext (HTTP). " +
                        "This is unacceptable for any production or internet-facing service."
            )
        } else {
            if (tls.port !in 1..65535) {
                errorList.add("tls.port must be between 1 and 65535")
            }
            if (tls.port != 443) {
                lumina.warn("TLS is running on non-standard port ${tls.port} (standard is 443)")
            }

            if (!tls.hsts.enabled) {
                lumina.warn(
                    "HSTS IS DISABLED – Browsers will not enforce HTTPS. " +
                            "Enable HSTS in production to prevent SSL-stripping attacks."
                )
            } else {
                if (tls.hsts.maxAgeInSeconds <= Duration.ZERO) {
                    errorList.add("tls.hsts.maxAgeInSeconds must be > 0 when HSTS is enabled")
                }
                if (tls.hsts.maxAgeInSeconds < 31536000.seconds) {
                    lumina.warn("HSTS max-age < 1 year – recommended minimum is 31536000 seconds (1 year)")
                }
                if (!tls.hsts.includeSubdomains) {
                    lumina.warn("HSTS does not include subdomains – subdomains remain vulnerable")
                }
            }
        }

        // ====================== CSRF ======================
        if (!csrf.enabled) {
            lumina.warn(
                "CSRF PROTECTION IS DISABLED – Application is vulnerable to Cross-Site Request Forgery attacks. " +
                        "Enable CSRF protection unless you have robust alternative mitigations (SameSite=Strict + double-submit cookie, etc.)."
            )
        } else {
            val hasValidation = csrf.originMatchesHost ||
                    csrf.allowedOrigins.isNotEmpty() ||
                    csrf.headerChecks.isNotEmpty()

            if (!hasValidation) {
                errorList.add(
                    "CSRF enabled but NO validation method configured " +
                            "(originMatchesHost=false, allowedOrigins empty, headerChecks empty) → protection is ineffective"
                )
            }

            if (csrf.headerChecks.isEmpty()) {
                lumina.warn("CSRF enabled but no header checks configured – relying solely on cookie-based token (weaker)")
            }
        }

        // ====================== Rate Limiting ======================
        if (!rateLimit.enabled) {
            lumina.warn("GLOBAL RATE LIMITING IS DISABLED – No protection against brute-force, credential stuffing, or DoS attacks.")
        } else {
            if (rateLimit.window <= Duration.ZERO) errorList.add("rateLimit.window must be > 0")
            if (rateLimit.maxRequests <= 0) errorList.add("rateLimit.maxRequests must be > 0")
        }

        // ====================== Password Policy ======================
        if (account.passwordPolicy.minLength < 8) {
            lumina.warn("Password minimum length is ${account.passwordPolicy.minLength} – passwords shorter than 8 characters are considered weak by modern standards.")
        }
        if (account.passwordPolicy.minLength < 1) {
            errorList.add("account.passwordPolicy.minLength must be ≥ 1")
        }

        // ====================== Session Lifetime ======================
        if (session.validFor > 30.days) {
            lumina.warn("Session lifetime is ${session.validFor.inWholeDays} days – very long-lived sessions increase risk if tokens are stolen.")
        }

        // ====================== Database Secrets ======================
        if (database.name.trim() == ConfigDefaults.database.name.trim()) {
            errorList.add("database.name is still the default placeholder – MUST be changed")
        }
        if (database.username.trim() == ConfigDefaults.database.username.trim()) {
            errorList.add("database.username is still the default placeholder – MUST be changed")
        }
        if (database.password.trim() == ConfigDefaults.database.password.trim()) {
            errorList.add("database.password is still the default placeholder – MUST be changed before use")
        } else if (database.password.isBlank()) {
            lumina.warn("Database password is empty – this is a critical security risk")
        }

        // ====================== MFA Defaults Still Present ======================
        if (mfa.totp.issuer.trim() == "Vayen Auth" || mfa.totp.issuer.isBlank()) {
            errorList.add("mfa.totp.issuer must be changed from default/value cannot be blank")
        }
        if (mfa.webAuthn.relyingPartyID == ConfigDefaults.mfa.webAuthn.relyingPartyID ||
            mfa.webAuthn.relyingPartyID.isBlank()
        ) {
            errorList.add("mfa.webAuthn.relyingPartyID must be set to your actual domain")
        }
        if (mfa.webAuthn.relyingPartyOrigins == ConfigDefaults.mfa.webAuthn.relyingPartyOrigins) {
            errorList.add("mfa.webAuthn.relyingPartyOrigins contains default values – must be customized")
        }

        // ====================== Other Hard Validation (unchanged) ======================
        if (database.host.isBlank()) errorList.add("database.host is required")
        if (database.port !in 1..65535) errorList.add("database.port invalid")
        if (database.maxConnections <= 0) errorList.add("database.maxConnections must be > 0")

        with(account.usernamePolicy) {
            if (minLength <= 0) errorList.add("usernamePolicy.minLength must be > 0")
            if (maxLength < minLength) errorList.add("usernamePolicy.maxLength must be ≥ minLength")
        }

        with(account.passwordPolicy) {
            if (maxLength < minLength) errorList.add("passwordPolicy.maxLength must be ≥ minLength")
            val totalReqSum = minLowercase + minUppercase + minNumbers + minSpecialCharacters
            if (totalReqSum > minLength) {
                errorList.add("Sum of password class requirements exceeds minLength")
            }
            if (minSpecialCharacters > 0 && allowedSpecialCharacters.isEmpty()) {
                errorList.add("minSpecialCharacters > 0 but no allowed special chars defined")
            }
        }

        if (session.validFor <= Duration.ZERO) errorList.add("session.validFor must be > 0")
        if (cache.sessionCacheSize <= 0L || cache.accountCacheSize <= 0L) {
            errorList.add("Cache sizes must be > 0")
        }

        // Final banner if any warnings were emitted
        if (errorList.isEmpty()) {
            lumina.info("Configuration validation passed – no fatal errors")
        }

        return errorList
    }
}


