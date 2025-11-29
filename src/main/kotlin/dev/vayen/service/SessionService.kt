/*
 * Vayen Auth (Vayen_Auth.main): SessionService.kt
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

package dev.vayen.service

import dev.vayen.data.Session
import dev.vayen.other.GeneralData
import dev.vayen.table.SessionTable
import mtctx.utilities.Outcome
import mtctx.utilities.crypto.HmacSha256
import mtctx.utilities.failure
import mtctx.utilities.runCatchingOutcomeOf
import mtctx.utilities.success
import org.jetbrains.exposed.sql.SqlExpressionBuilder.eq
import org.jetbrains.exposed.sql.deleteWhere
import org.jetbrains.exposed.sql.insert
import org.jetbrains.exposed.sql.selectAll
import java.util.*
import kotlin.time.Clock
import kotlin.time.ExperimentalTime
import kotlin.uuid.ExperimentalUuidApi

@OptIn(ExperimentalTime::class)
class SessionService(private val setup: GeneralData<UUID, Session>) : DatabaseService<UUID, Session>() {

    override suspend operator fun get(id: UUID): Outcome<Session> = runCatchingOutcomeOf<Session> {
        val session = setup.cache.get(id)
            ?: dbQuery {
                SessionTable.selectAll().where { SessionTable.uuid eq id }.map {
                    Session(
                        uuid = it[SessionTable.uuid],
                        userUUID = it[SessionTable.userUUID],
                        macKey = it[SessionTable.macKey],
                        createdAt = it[SessionTable.createdAt],
                        validFor = it[SessionTable.validFor],
                    )
                }.singleOrNull()
            } ?: return failure("Session not found")

        if (session.expired()) {
            return failure("Session Expired!")
        }
        session
    }

    suspend fun macKey(uuid: UUID): Outcome<ByteArray> = runCatchingOutcomeOf<ByteArray> {
        dbQuery {
            SessionTable.select(SessionTable.macKey).where { SessionTable.uuid eq uuid }.singleOrNull()
        }?.get(SessionTable.macKey)
            ?: throw IllegalStateException("Could not get the Mac Key from Session with UUID $uuid")
    }


    @OptIn(ExperimentalUuidApi::class)
    suspend fun create(ownerUUID: UUID): Outcome<String> = runCatchingOutcomeOf<String> {
        val generatedMacKey = HmacSha256.generateKey()
        val generatedUUID = UUID.randomUUID()
        val now = Clock.System.now()

        dbQuery {
            SessionTable.insert {
                it[uuid] = generatedUUID
                it[userUUID] = ownerUUID
                it[macKey] = generatedMacKey
                it[createdAt] = now
                it[validFor] = setup.config.session.validFor
            }
        }

        setup.cache.put(
            generatedUUID,
            Session(generatedUUID, ownerUUID, generatedMacKey, now, setup.config.session.validFor)
        )

        val macTag = HmacSha256.generate("$generatedUUID.${setup.config.session.validFor}", generatedMacKey)
        return success(buildSessionString(generatedUUID, macTag.tag))
    }

    override suspend fun delete(id: UUID) = runCatchingOutcomeOf<Unit> {
        setup.cache.remove(id)
        dbQuery {
            SessionTable.deleteWhere { SessionTable.uuid eq id }
        }
    }

    companion object {
        suspend fun splitUUIDAndMAC(uuidAndMac: String): Outcome<Pair<UUID, ByteArray>> =
            runCatchingOutcomeOf<Pair<UUID, ByteArray>> {
                val result = uuidAndMac.split(".")

                if (result.size != 2) {
                    return failure("invalid uuid and mac")
                }

                val parsedUUID = UUID.fromString(result[0].removePrefix("VA:"))
                val macTag = result[1].chunked(2).map { it.toInt(16).toByte() }.toByteArray()
                return success(parsedUUID to macTag)
            }

        fun buildSessionString(uuid: UUID, macTag: ByteArray): String =
            "VA:$uuid.${macTag.joinToString("") { "%02x".format(it) }}"
    }
}