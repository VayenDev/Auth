/*
 * Vayen Auth (Vayen_Auth.main): Application.kt
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

package dev.vayen

import dev.vayen.config.Config
import io.ktor.server.application.*
import io.ktor.server.cio.*
import io.ktor.server.engine.*
import kotlinx.datetime.TimeZone
import mtctx.lumina.v4.createLumina
import mtctx.utilities.fileSystem
import mtctx.utilities.readAndDeserialize
import mtctx.utilities.serialization.jsonForHumans
import mtctx.utilities.serializeAndWrite
import okio.Path.Companion.toPath
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

    val config = configPath.readAndDeserialize(Config.serializer(), jsonForHumans)

    val validationErrors = config.validate(lumina)
    if (validationErrors.isNotEmpty()) {
        lumina.error { validationErrors.forEach { line(it) } }
        exitProcess(1)
    }
    lumina.info("Using config file at $configPath")

    embeddedServer(CIO, port = config.port, host = "0.0.0.0", module = Application::module)
        .start(wait = true)
}

fun Application.module() {
    setupPlugins()
    configureDatabase()
}
