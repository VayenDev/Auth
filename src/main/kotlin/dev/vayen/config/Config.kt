/*
 * Vayen Auth (Vayen_Auth.main): Config.kt
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

package dev.vayen.config

import kotlinx.serialization.Serializable
import mtctx.lumina.v4.Lumina
import kotlin.time.Duration

@Serializable
data class Config(
    val database: DatabaseConfig,
    val session: SessionConfig,
    val tls: TLSConfig,
    val rateLimit: RateLimitConfig,
    val cache: CacheConfig,
    val mfa: MFAConfig,
    val port: Int
) {
    companion object {
        val default = Config(
            ConfigDefaults.database,
            ConfigDefaults.session,
            ConfigDefaults.tls,
            ConfigDefaults.rateLimit,
            ConfigDefaults.cache,
            ConfigDefaults.mfa,
            ConfigDefaults.port
        )
    }

    suspend fun validate(lumina: Lumina): Set<String> {
        val errorList = mutableSetOf<String>()

        // General Config validation
        if (port == 0) {
            errorList.add("port is required")
        }

        // Database Config validation
        if (database.host.isBlank()) {
            errorList.add("database host is required")
        }
        if (database.port !in 1..65535) {
            errorList.add("database port must be between 1 and 65535")
        }
        if (database.name.isBlank()) {
            errorList.add("database name is required")
        }
        if (database.name.trim() == ConfigDefaults.database.name.trim()) {
            errorList.add("database name must be changed, it cannot be the default")
        }
        if (database.username.isBlank()) {
            errorList.add("database username is required")
        }
        if (database.username.trim() == ConfigDefaults.database.username.trim()) {
            errorList.add("database username must be changed, it cannot be the default")
        }
        if (database.password.isBlank()) {
            lumina.warn("database password is empty, we recommend using a password for security reasons!")
        }
        if (database.password.trim() == ConfigDefaults.database.password.trim()) {
            errorList.add("database password must be changed, it cannot be the default")
        }

        // Session Config validation
        if (session.validFor == Duration.ZERO) {
            errorList.add("duration length for a session validity is required")
        }

        // TLS Config validation
        if (!tls.enabled) {
            lumina.warn("TLS is disabled, we recommend using TLS for security reasons")
        } else {
            if (tls.certFile.isBlank()) {
                lumina.warn("TLS certificate file is empty, we recommend using a certificate for security reasons so that the server can use TLS")
            }
            if (tls.keyFile.isBlank()) {
                lumina.warn("TLS key file is empty, we recommend using a key for security reasons so that the server can use TLS")
            }
        }

        // Cache Config validation
        if (cache.sessionCacheSize == 0L) {
            errorList.add("session cache size is required")
        }
        if (cache.accountCacheSize == 0L) {
            errorList.add("account cache size is required")
        }
        if (cache.rateLimitCacheSize == 0L) {
            errorList.add("rate limit cache size is required")
        }

        // MFA Config validation
        if (mfa.totp.issuer.isBlank()) {
            errorList.add("TOTP issuer is required")
        }
        if (mfa.totp.issuer == "Vayen Auth") {
            errorList.add("TOTP issuer is set to default, set it to something else for security reasons")
        }
        if (mfa.totp.imageWidth == 0) {
            errorList.add("TOTP image width is required")
        }
        if (mfa.totp.imageHeight == 0) {
            errorList.add("TOTP image height is required")
        }

        if (mfa.webAuthn.relyingPartyOrigins.isEmpty()) {
            errorList.add("webauthn relying party origins are required")
        }
        if (mfa.webAuthn.relyingPartyOrigins == ConfigDefaults.mfa.webAuthn.relyingPartyOrigins) {
            errorList.add("WebAuthn relying party origins are set to default, set them to something else for security reasons")
        }

        if (mfa.webAuthn.relyingPartyID.isBlank()) {
            errorList.add("webauthn relying party id is required")
        }
        if (mfa.webAuthn.relyingPartyID == ConfigDefaults.mfa.webAuthn.relyingPartyID) {
            errorList.add("webauthn relying party id is set to default, set it to something else for security reasons")
        }
        if (mfa.webAuthn.relyingPartyDisplayName.isBlank()) {
            errorList.add("webauthn relying party display name is required")
        }
        if (mfa.webAuthn.relyingPartyDisplayName == ConfigDefaults.mfa.webAuthn.relyingPartyDisplayName) {
            errorList.add("webauthn relying party display name is set to default, set it to something else for security reasons")
        }

        return errorList
    }
}

@Serializable
data class DatabaseConfig(
    val host: String,
    val port: Int,
    val name: String,
    val username: String,
    val password: String,
    val maxConnections: Int
)

@Serializable
data class SessionConfig(
    val validFor: Duration
)

@Serializable
data class TLSConfig(
    val enabled: Boolean,
    val certFile: String,
    val keyFile: String
)

@Serializable
data class RateLimitConfig(
    val enabled: Boolean,
    val window: Duration,
    val maxRequests: Int
)

@Serializable
data class CacheConfig(
    val sessionCacheSize: Long,
    val accountCacheSize: Long,
    val rateLimitCacheSize: Long
)

@Serializable
data class MFAConfig(
    val totp: TOTPConfig,
    val webAuthn: WebAuthnConfig
)

@Serializable
data class TOTPConfig(
    val issuer: String,
    val imageWidth: Int,
    val imageHeight: Int
)

@Serializable
data class WebAuthnConfig(
    val relyingPartyDisplayName: String,
    val relyingPartyID: String,
    val relyingPartyOrigins: List<String>
)
