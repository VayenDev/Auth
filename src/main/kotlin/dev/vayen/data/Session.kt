/*
 * Vayen Auth (Vayen_Auth.main): Session.kt
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

import dev.vayen.other.SerializableUUID
import dev.vayen.service.SessionService
import io.ktor.server.sessions.*
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.Serializable
import mtctx.utilities.flatMap
import java.util.*
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

@OptIn(ExperimentalTime::class)
@Serializable
class Session(
    val uuid: SerializableUUID,
    val userUUID: SerializableUUID,
    val macKey: ByteArray,
    val createdAt: Instant,
    val validFor: Duration,
    val cookieValue: String // Format: VA:uuid.<macTag by uuid:validFor>
) {
    fun expired(): Boolean = createdAt.plus(validFor) < Clock.System.now()

    class Serializer(private val sessionService: SessionService) : SessionSerializer<Session> {
        override fun deserialize(text: String): Session = runBlocking {
            SessionService.splitUUIDAndMAC(text).flatMap { (uuid, macTag) ->
                sessionService.getAndCheck(uuid, macTag)
            }.getOrNull() ?: throw IllegalArgumentException("Invalid or Tampered Session!")
        }

        override fun serialize(session: Session): String = session.cookieValue
    }
}


@Serializable
data class CSRFSession(
    val csrfToken: String = UUID.randomUUID().toString()
)