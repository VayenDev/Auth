/*
 * Vayen Auth (Vayen_Auth.main): Route.kt
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

package dev.vayen.route

import dev.vayen.data.Session
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.server.sessions.*

suspend fun ApplicationCall.getAndCheckSession(): Session? = sessions.get<Session>() ?: run {
    respond<Body.ErrorResponse>(HttpStatusCode.Unauthorized, Body.ErrorResponse("Session not found in cookies!"))
    null
}