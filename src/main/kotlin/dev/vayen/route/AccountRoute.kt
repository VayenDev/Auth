/*
 * Vayen Auth (Vayen_Auth.main): AccountRoute.kt
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

import dev.vayen.data.CSRFSession
import dev.vayen.data.ContextKey.Data.currentAccount
import dev.vayen.data.ContextKey.Service.accountService
import dev.vayen.data.ContextKey.Service.sessionService
import dev.vayen.data.ContextKey.config
import dev.vayen.data.Session
import dev.vayen.other.LeetChecker
import io.ktor.http.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.sessions.*
import mtctx.utilities.Outcome


fun Route.accountRoute() = route("/account") {
    post("/register") {
        val (username, password) = accountValidateUsernameAndPassword() ?: return@post

        //  ================ USERNAME CHECKING ================
        if (username.length < config.account.usernamePolicy.minLength) {
            call.respond<Body.BasicResponse>(
                HttpStatusCode.BadRequest,
                Body.BasicResponse("Username too short! Min length: ${config.account.usernamePolicy.minLength}")
            )
            return@post
        }

        if (username.length > config.account.usernamePolicy.maxLength) {
            call.respond<Body.BasicResponse>(
                HttpStatusCode.BadRequest,
                Body.BasicResponse("Username too long! Max length: ${config.account.usernamePolicy.maxLength}")
            )
            return@post
        }

        if (username.any { it in config.account.usernamePolicy.blockedCharacters }) {
            call.respond<Body.BasicResponse>(
                HttpStatusCode.BadRequest,
                Body.BasicResponse(
                    "Username contains blocked characters! Blocked characters: ${
                        config.account.usernamePolicy.blockedCharacters.joinToString(", ")
                    }"
                )
            )
            return@post
        }

        if (LeetChecker.containsBannedWord(username, config.account.usernamePolicy.blockedWords)) {
            call.respond<Body.BasicResponse>(
                HttpStatusCode.BadRequest,
                Body.BasicResponse("Username contains one or multiple banned words!")
            )
            return@post
        }

        // ================ PASSWORD CHECKING ================
        if (password.length < config.account.passwordPolicy.minLength) {
            call.respond<Body.BasicResponse>(
                HttpStatusCode.BadRequest,
                Body.BasicResponse("Password too short! Min length: ${config.account.passwordPolicy.minLength}")
            )
            return@post
        }
        if (password.length > config.account.passwordPolicy.maxLength) {
            call.respond<Body.BasicResponse>(
                HttpStatusCode.BadRequest,
                Body.BasicResponse("Password too long! Max length: ${config.account.passwordPolicy.maxLength}")
            )
        }

        val passwordRegex =
            "^(?=.{${config.account.passwordPolicy.minLength},${config.account.passwordPolicy.maxLength}}$)(?=(?:.*[a-z]){${config.account.passwordPolicy.minLowercase}})(?=(?:.*[A-Z]){${config.account.passwordPolicy.minUppercase}})(?=(?:.*[0-9]){${config.account.passwordPolicy.minNumbers}})(?=(?:.*[${
                config.account.passwordPolicy.allowedSpecialCharacters.joinToString(
                    ","
                )
            }]){${config.account.passwordPolicy.minSpecialCharacters}}).*$".toRegex()

        if (!passwordRegex.matches(password)) {
            call.respond<Body.BasicResponse>(
                HttpStatusCode.BadRequest,
                Body.BasicResponse(
                    """
                        Password does not meet requirements!
                        Requirements:
                        - Min length: ${config.account.passwordPolicy.minLength}
                        - Max length: ${config.account.passwordPolicy.maxLength}
                        - Min lowercase: ${config.account.passwordPolicy.minLowercase}
                        - Min uppercase: ${config.account.passwordPolicy.minUppercase}
                        - Min numbers: ${config.account.passwordPolicy.minNumbers}
                        - Min special characters: ${config.account.passwordPolicy.minSpecialCharacters}
                        - Allowed special characters: ${
                        config.account.passwordPolicy.allowedSpecialCharacters.joinToString(
                            ", "
                        )
                    }
                    """.trimIndent()
                )
            )
            return@post
        }

        return@post when (val creationOutcome = accountService.create(username, password)) {
            is Outcome.Success -> call.respond<Body.BasicResponse>(
                HttpStatusCode.Created,
                Body.BasicResponse("Account created successfully, please login.")
            )

            is Outcome.Failure -> call.respond<Body.ErrorResponse>(
                HttpStatusCode.InternalServerError,
                Body.ErrorResponse(
                    "An error occurred while creating your account, please try again later.",
                    setOf(creationOutcome.message)
                )
            )
        }
    }

    post("/login") {
        val (username, password) = accountValidateUsernameAndPassword() ?: return@post

        return@post when (val loginOutcome = accountService.login(sessionService, username, password)) {
            is Outcome.Success -> {
                call.sessions.set(loginOutcome.value)
                call.sessions.set(CSRFSession())
                call.respond<Body.BasicResponse>(HttpStatusCode.OK, Body.BasicResponse("Logged in successfully."))
            }

            is Outcome.Failure -> call.respond<Body.ErrorResponse>(
                HttpStatusCode.InternalServerError,
                Body.ErrorResponse(
                    "An error occurred while logging you in into your account, please try again later.",
                    setOf(loginOutcome.message)
                )
            )
        }
    }

    post("/change_password") {
        val body = call.receive<Body.UsernameAndPassword>()

        if (body.password.isBlank()) {
            call.respond<Body.BasicResponse>(
                HttpStatusCode.BadRequest,
                Body.BasicResponse("Username and password are required!")
            )
            return@post
        }

        val updatePasswordOutcome = accountService.updatePassword(currentAccount.uuid, body.password.trim())

        return@post when (updatePasswordOutcome) {
            is Outcome.Success -> call.respond<Body.BasicResponse>(
                HttpStatusCode.OK,
                Body.BasicResponse("Password updated successfully.")
            )

            is Outcome.Failure -> call.respond<Body.ErrorResponse>(
                HttpStatusCode.InternalServerError,
                Body.ErrorResponse(
                    "An error occurred while updating your password, please try again later.",
                    setOf(updatePasswordOutcome.message)
                )
            )
        }
    }

    delete("/delete") {
        return@delete when (val deleteOutcome = accountService.delete(currentAccount.uuid)) {
            is Outcome.Success -> call.respond<Body.BasicResponse>(
                HttpStatusCode.OK,
                Body.BasicResponse("Account deleted successfully.")
            )

            is Outcome.Failure -> call.respond<Body.ErrorResponse>(
                HttpStatusCode.InternalServerError,
                Body.ErrorResponse(
                    "An error occurred while deleting your account, please try again later.",
                    setOf(deleteOutcome.message)
                )
            )
        }
    }

    post("/logout") {
        val session = call.getAndCheckSession() ?: return@post
        val deleteOutcome = sessionService.delete(session.uuid)
        return@post when (deleteOutcome) {
            is Outcome.Success -> {
                call.sessions.clear<Session>()
                call.respond<Body.BasicResponse>(
                    HttpStatusCode.OK,
                    Body.BasicResponse("Logged out successfully.")
                )
            }

            is Outcome.Failure -> call.respond<Body.ErrorResponse>(
                HttpStatusCode.InternalServerError,
                Body.ErrorResponse("An error occurred while logging you out, please try again later.")
            )
        }
    }
}

suspend fun RoutingContext.accountValidateUsernameAndPassword(): Pair<String, String>? {
    val body = call.receive<Body.UsernameAndPassword>()

    if (body.username.isBlank() || body.password.isBlank()) {
        call.respond<Body.BasicResponse>(
            HttpStatusCode.BadRequest,
            Body.BasicResponse("Username and password are required!")
        )
        return null
    }

    return body.username.trim() to body.password.trim()
}