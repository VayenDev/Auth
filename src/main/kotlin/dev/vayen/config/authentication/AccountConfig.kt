/*
 * Vayen Auth (Vayen_Auth.main): AccountConfig.kt
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

package dev.vayen.config.authentication

import kotlinx.serialization.Serializable

@Serializable
data class AccountConfig(
    val usernamePolicy: UsernamePolicyConfig,
    val passwordPolicy: PasswordPolicyConfig,
) {
    @Serializable
    data class UsernamePolicyConfig(
        val blockedCharacters: List<Char>,
        var blockedWords: List<String>,
        val minLength: Int,
        val maxLength: Int,
    )

    @Serializable
    data class PasswordPolicyConfig(
        val minLength: Int,
        val maxLength: Int,
        val minLowercase: Int,
        val minUppercase: Int,
        val minNumbers: Int,
        val minSpecialCharacters: Int,
        val allowedSpecialCharacters: List<Char>
    )
}