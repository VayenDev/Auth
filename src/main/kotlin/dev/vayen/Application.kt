/*
 * Vayen Auth (Vayen_Auth.main): Application.kt
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

import com.mayakapps.kache.InMemoryKache
import dev.vayen.config.Config
import dev.vayen.data.CSRFSession
import dev.vayen.data.Session
import dev.vayen.route.accountRoute
import dev.vayen.route.sessionRoute
import dev.vayen.service.AccountService
import dev.vayen.service.SessionService
import io.ktor.http.*
import io.ktor.server.cio.*
import io.ktor.server.engine.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.sessions.*
import kotlinx.datetime.TimeZone
import mtctx.lumina.v4.createLumina
import mtctx.utilities.fileSystem
import mtctx.utilities.readAndDeserialize
import mtctx.utilities.runCatchingOutcomeOf
import mtctx.utilities.serialization.jsonForHumans
import mtctx.utilities.serializeAndWrite
import okio.Path.Companion.toPath
import org.jetbrains.exposed.sql.Database
import java.util.*
import kotlin.system.exitProcess

suspend fun main() {
    val lumina = createLumina {
        name = "Vayen Auth"
        timeZone = TimeZone.currentSystemDefault()
    }

    val configPath = fileSystem.canonicalize("./config.json".toPath())
    if (!fileSystem.exists(configPath)) {
        Config.default.serializeAndWrite(Config.serializer(), configPath, false, format = jsonForHumans)
        lumina.info("Created default config file at $configPath")
        exitProcess(0)
    }

    val config = configPath.readAndDeserialize(Config.serializer(), jsonForHumans).getOrNull() ?: run {
        lumina.error("Error while reading and deserializing config! Exiting...")
        exitProcess(1)
    }
    config.account.usernamePolicy.blockedWords = config.account.usernamePolicy.blockedWords
        .map { it.lowercase(Locale.ROOT) }
        .distinct()
        .sortedBy { it.length }
        .toList()
        .also {
            lumina.info("Loaded ${it.size} banned words.")
        }

    val validationErrors = config.validate(lumina)
    if (validationErrors.isNotEmpty()) {
        lumina.error { validationErrors.forEach { line(it) } }
        exitProcess(1)
    }
    lumina.info("Using config file at $configPath")

    lumina.info("Connecting to database at ${config.database.host}:${config.database.port}")
    val database = runCatchingOutcomeOf {
        Database.connect(
            "jdbc:postgresql://${config.database.host}:${config.database.port}/${config.database.name}",
            driver = "org.postgresql.Driver",
            user = config.database.username,
            password = config.database.password
        )
    }.getOrNull() ?: run {
        lumina.error("Error while connecting to database! Exiting...")
        exitProcess(1)
    }

    lumina.info("Setting up caches...")

    val accountService =
        AccountService(config, lumina, database, InMemoryKache(config.cache.accountCacheSize))
    val sessionService =
        SessionService(config, lumina, database, InMemoryKache(config.cache.sessionCacheSize))

    embeddedServer(CIO, port = config.port, host = "localhost") {
        setupPlugins(config, lumina, database, accountService, sessionService)
        routing {
            get("/csrf/refresh") {
                call.sessions.get<Session>() ?: return@get call.respond(HttpStatusCode.Unauthorized)
                call.sessions.set(CSRFSession())
                call.respond(HttpStatusCode.OK)
            }

            accountRoute()
            sessionRoute()
        }
    }.start(wait = true)
}
