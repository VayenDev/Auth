/*
 * Vayen Auth (Vayen_Auth.main): AccountService.kt
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

import dev.vayen.data.Account
import dev.vayen.other.GeneralData
import dev.vayen.table.AccountTable
import dev.vayen.table.SessionTable
import dev.vayen.table.mfa.MFATOTPTable
import dev.vayen.table.mfa.MFAWebAuthnTable
import mtctx.utilities.*
import mtctx.utilities.crypto.Argon2
import mtctx.utilities.crypto.SECURE_RANDOM
import org.bouncycastle.util.encoders.Base32
import org.jetbrains.exposed.sql.*
import org.jetbrains.exposed.sql.SqlExpressionBuilder.eq
import java.util.*

class AccountService(private val setup: GeneralData<UUID, Account>) : DatabaseService<UUID, Account>() {
    init {
        SchemaUtils.create(AccountTable, MFATOTPTable, MFAWebAuthnTable)
    }

    private fun <T> get(column: ExpressionWithColumnType<T>, type: T): Account? =
        AccountTable.selectAll().where { column eq type }.map {
            Account(
                uuid = it[AccountTable.uuid],
                username = it[AccountTable.username],
                passwordHash = it[AccountTable.passwordHash],
                webhookUUID = it[AccountTable.webhookUUID],
                recoveryCodes = it[AccountTable.recoveryCodes]
            )
        }.singleOrNull()

    override suspend operator fun get(
        id: UUID
    ): Outcome<Account> = runCatchingOutcomeOf<Account> {
        val account =
            setup.cache.get(id)
                ?: dbQuery { get(AccountTable.uuid, id) }
                ?: return failure("Account not found")
        account
    }

    suspend fun getByUsername(username: String): Outcome<Account> =
        dbQuery { get(AccountTable.username, username) }?.let { success(it) } ?: failure("Account not found")

    suspend fun getByWebhookUUID(webhookUUID: UUID): Outcome<Account> =
        dbQuery { get(AccountTable.webhookUUID, webhookUUID) }?.let { success(it) } ?: failure("Account not found")

    suspend fun getBySession(sessionUUID: UUID): Outcome<Account> = runCatchingOutcomeOf<Account> {
        dbQuery {
            (SessionTable innerJoin AccountTable)
                .selectAll()
                .where { SessionTable.uuid eq sessionUUID }
                .map {
                    Account(
                        uuid = it[AccountTable.uuid],
                        username = it[AccountTable.username],
                        passwordHash = it[AccountTable.passwordHash],
                        webhookUUID = it[AccountTable.webhookUUID],
                        recoveryCodes = it[AccountTable.recoveryCodes]
                    )
                }.singleOrNull()
        } ?: return failure("No user found for the given session UUID")
    }

    suspend fun recoveryCodes(uuid: UUID): Outcome<List<String>> = this[uuid].mapCatching { it.recoveryCodes }

    suspend fun checkPassword(uuid: UUID, unhashedPassword: String): Outcome<Boolean> =
        this[uuid].mapCatching { return Argon2.verify(unhashedPassword, it.passwordHash) }

    suspend fun updatePassword(uuid: UUID, newPassword: String): Outcome<Unit> = runCatchingOutcomeOf<Unit> {
        dbQuery {
            AccountTable.update({ AccountTable.uuid eq uuid }) {
                it[AccountTable.passwordHash] = Argon2.hash(newPassword).hash
            }
            SessionTable.deleteWhere { SessionTable.userUUID eq uuid }
        }
    }

    suspend fun login(sessionService: SessionService, username: String, password: String): Outcome<String> =
        getByUsername(username).mapCatching { account ->
            val correctPassword = Argon2.verify(password, account.passwordHash).getOrNull()
                ?: return failure("Could not check passwords!")
            if (!correctPassword) return failure("Incorrect password!")

            return sessionService.create(account.uuid)
        }

    suspend fun create(username: String, password: String): Outcome<Unit> = runCatchingOutcomeOf<Unit> {
        dbQuery {
            if (AccountTable.selectAll().where { AccountTable.username eq username }.limit(1)
                    .any()
            ) throw IllegalStateException("Username is taken.")

            AccountTable.insert {
                it[AccountTable.uuid] = UUID.randomUUID()
                it[AccountTable.username] = username
                it[AccountTable.passwordHash] = Argon2.hash(password).hash
                it[AccountTable.webhookUUID] = UUID.randomUUID()
                it[AccountTable.recoveryCodes] = generateAccountRecoveryCodes(5)
            }
        }
    }


    override suspend fun delete(id: UUID): Outcome<Unit> = runCatchingOutcomeOf<Unit> {
        setup.cache.remove(id)
        dbQuery {
            AccountTable.deleteWhere { AccountTable.uuid eq id }
            SessionTable.deleteWhere { SessionTable.userUUID eq id }
        }
    }

    companion object {
        fun generateAccountRecoveryCodes(n: Int): List<String> {
            return List(n) {
                val bytes = ByteArray(10)
                SECURE_RANDOM.nextBytes(bytes)
                Base32.toBase32String(bytes).uppercase()
            }
        }
    }
}
