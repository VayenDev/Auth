/*
 * Vayen Auth (Vayen_Auth.main): LeetChecker.kt
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

package dev.vayen.other

object LeetChecker {

    // 0 = no mapping, otherwise maps to that char
    private val LEET_MAP = ByteArray(128).apply {
        // a
        this['4'.code] = 'a'.code.toByte()
        this['@'.code] = 'a'.code.toByte()
        this['/'.code] = 'a'.code.toByte()  // /\
        this['^'.code] = 'a'.code.toByte()

        // b
        this['8'.code] = 'b'.code.toByte()

        // c
        this['('.code] = 'c'.code.toByte()
        this['['.code] = 'c'.code.toByte()
        this['{'.code] = 'c'.code.toByte()

        // e
        this['3'.code] = 'e'.code.toByte()

        // i
        this['1'.code] = 'i'.code.toByte()
        this['!'.code] = 'i'.code.toByte()
        this['|'.code] = 'i'.code.toByte()
        this['l'.code] = 'i'.code.toByte()
        this['í'.code] = 'i'.code.toByte()
        this['ì'.code] = 'i'.code.toByte()
        this['î'.code] = 'i'.code.toByte()

        // o
        this['0'.code] = 'o'.code.toByte()

        // s
        this['5'.code] = 's'.code.toByte()
        this['$'.code] = 's'.code.toByte()
        this['z'.code] = 's'.code.toByte()
        this['§'.code] = 's'.code.toByte()

        // t
        this['7'.code] = 't'.code.toByte()
        this['+'.code] = 't'.code.toByte()
        this['†'.code] = 't'.code.toByte()
    }

    fun containsBannedWord(input: String, bannedWords: List<String>): Boolean {
        if (input.length < 3) return false
        val chars = CharArray(input.length)
        for (i in input.indices) {
            chars[i] = input[i].lowercaseChar()
        }

        return bannedWords.any { target ->
            matches(target, chars)
        }
    }

    private fun matches(target: String, input: CharArray): Boolean {
        var tp = 0
        var ip = 0
        val tLen = target.length
        val iLen = input.size

        while (tp < tLen && ip < iLen) {
            var tc = target[tp]
            var ic = input[ip]

            // Direct match
            if (tc == ic) {
                tp++; ip++; continue
            }

            // Leet substitution (fast path)
            if (ic.code < 128) {
                val mapped = LEET_MAP[ic.code]
                if (mapped.toInt() != 0 && mapped.toChar() == tc) {
                    tp++; ip++; continue
                }
            }

            // Multi-char common bypasses
            when {
                tc == 'f' && ip + 1 < iLen && input[ip] == 'p' && input[ip + 1] == 'h' -> {
                    ip += 2; tp++; continue
                }

                tc == 'k' && ip + 1 < iLen && input[ip] == 'c' && input[ip + 1] == 'k' -> {
                    ip += 2; tp++; continue
                }

                tc == 'a' && ip + 1 < iLen && input[ip] == '/' && input[ip + 1] == '\\' -> {
                    ip += 2; tp++; continue
                }

                tc == 's' && ip + 1 < iLen && input[ip] == '§' -> {  // § -> s
                    ip++; tp++; continue
                }

                // Allow common separators: *, _, ., -, space, etc.
                // This catches: f*u*c*k, f.u.c.k, fuck_you, etc.
                else -> {
                    if (isSeparator(ic)) {
                        ip++          // skip separator in input
                        continue
                    }
                    return false
                }
            }
        }

        // Allow trailing garbage (common in usernames)
        while (ip < iLen) {
            val c = input[ip++]
            if (!isSeparator(c) && (c.code >= 128 || LEET_MAP[c.code].toInt() == 0)) {
                return false  // non-separator, non-leet char → not a match
            }
        }

        return tp == tLen
    }

    private fun isSeparator(c: Char): Boolean =
        c == ' ' || c == '_' || c == '-' || c == '.' || c == '*' || c == ',' || c == ':'
}