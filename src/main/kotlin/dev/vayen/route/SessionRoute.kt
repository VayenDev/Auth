/*
 * Vayen Auth (Vayen_Auth.main): SessionRoute.kt
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

import dev.vayen.data.ContextKey.Service.sessionService
import dev.vayen.data.Session
import io.ktor.http.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.sessions.*

fun Route.sessionRoute() = route("/session") {
    get("/expired") {
        val session = call.getAndCheckSession() ?: return@get
        var expired = ""

        if (session.expired()) {
            expired = "Session expired and invalidated now."
            call.sessions.clear<Session>()
            sessionService.delete(session.uuid)
        } else {
            expired = "Session is valid."
        }

        return@get call.respond<Body.BasicResponse>(HttpStatusCode.OK, Body.BasicResponse(expired))
    }
    delete("/invalidate") {
        val session = call.getAndCheckSession() ?: return@delete
        call.sessions.clear<Session>()
        sessionService.delete(session.uuid)
        return@delete call.respond<Body.BasicResponse>(HttpStatusCode.OK, Body.BasicResponse("Session invalidated."))
    }

}