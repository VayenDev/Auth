/*
 * Vayen Auth (Vayen_Auth.main): DefaultBannedWords.kt
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

package dev.vayen.config

val DefaultBannedWords: List<String> = listOf(
    "abortion", "anal", "analsex", "anus", "arse", "ass", "asshole", "assholes", "asslick",
    "asswipe", "bastard", "beastiality", "beastility", "bellend", "bestiality", "bitch",
    "bitches", "bitchass", "blowjob", "bollock", "boner", "boob", "boobs", "bugger",
    "bum", "butt", "butthole", "buttplug", "chink", "clit", "clitoris", "cock", "cockhead",
    "cocks", "cocksucker", "coon", "cum", "cummer", "cumming", "cumshot", "cunilingus",
    "cunnilingus", "cunt", "cuntlick", "cuntlicker", "cuntface", "dago", "damn", "deggo",
    "dick", "dickhead", "dike", "dildo", "dogging", "donkeypunch", "douche", "dyke",
    "fag", "faggot", "faggots", "fagtard", "fanny", "fatass", "fellatio", "felch",
    "fisting", "flamer", "fuck", "fucker", "fuckface", "fucktard", "fuckwit", "fudgepacker",
    "gay", "gaysex", "gook", "gyppo", "handjob", "homo", "hooker", "horniest", "horny",
    "jackoff", "jap", "jerkoff", "jew", "jigaboo", "jizz", "kike", "kooch", "kootch",
    "kraut", "kunt", "kyke", "labia", "lezzie", "lust", "mafugly", "masturbate", "milf",
    "motherfucker", "muff", "muffdiver", "nazi", "negro", "nigger", "nigga", "niglet",
    "nignog", "orgasm", "paedophile", "paki", "panooch", "pecker", "pedophile", "penis",
    "piss", "pissflaps", "piss off", "poof", "poon", "poontang", "porn", "prick", "prick",
    "pube", "pussy", "queef", "queer", "raghead", "rape", "rapist", "raunch", "rectum",
    "retard", "rimjob", "rimming", "ruski", "sandnigger", "scat", "schlong", "semen",
    "sex", "shag", "shemale", "shit", "shithead", "shitstain", "shota", "skank", "slut",
    "smeg", "smegma", "snatch", "spastic", "spic", "spick", "spunk", "suck", "tard",
    "testicle", "tit", "titfuck", "tits", "titty", "tittyfuck", "tranny", "twat", "twatlips",
    "twunt", "vagina", "viagra", "vulva", "wank", "wetback", "whore", "wop", "xxx",
    "zoophilia",

    // Extra compounds & highly toxic terms
    "4r5e", "5h1t", "ahole", "asshat", "assmunch", "beaner", "bitchboy", "bitchslap",
    "bitchtits", "blow job", "bullshit", "bum boy", "camel jockey", "carpet muncher",
    "chinc", "chinky", "cockbite", "cockburger", "cockgoblin", "cockjockey", "cockknocker",
    "cockmongler", "cocknose", "cocknugget", "cocksplurt", "cockwaffle", "coochie",
    "coochy", "coonass", "cracker", "cumbubble", "cumdump", "cumdumpster", "cumguzzler",
    "cumjockey", "cumqueen", "cumrag", "cumslut", "cumtart", "cuntbag", "cuntnugget",
    "cuntpunch", "cuntslut", "darkie", "dickbag", "dickface", "dickless", "dickmilk",
    "dickweed", "dogfucker", "douchebag", "douchewaffle", "dumbfuck", "dumbshit", "fagbag",
    "fagfucker", "fagtits", "fagtron", "fatfuck", "fuckass", "fuckboy", "fuckbrain",
    "fuckbutt", "fuckhole", "fucknut", "fucknugget", "fuckoff", "fuckpig", "fuckstain",
    "fuckstick", "fucktrophy", "fuckwad", "gangbang", "gash", "ghetto", "gobshite",
    "gookeye", "gooch", "gyp", "heeb", "hillbilly", "hitler", "holocaust", "injunior",
    "jizzmopper", "junglebunny", "kike", "knob", "knobhead", "kyke", "lezz", "lezzo",
    "limpdick", "mcfagget", "mick", "minge", "mong", "moolie", "mooncricket", "muffdiving",
    "munging", "nig", "niggress", "nobjockey", "nobjocky", "nutcase", "nutsack", "pisshead",
    "pisspig", "polack", "poofter", "porchmonkey", "punani", "pussylick", "ragamuffin",
    "ragtard", "redskin", "renob", "rimjaw", "ruskie", "sambo", "scrote", "shitass",
    "shitbag", "shitbreath", "shitcunt", "shitdick", "shitface", "shitfucker", "shitspitter",
    "shittits", "skullfuck", "slag", "slanteye", "slope", "slopehead", "smeghead",
    "snigger", "sodoff", "spacker", "spade", "spermbag", "spic", "spig", "spik", "splooge",
    "spook", "suckass", "tacobender", "tard", "titbag", "titjob", "titlicker", "titwank",
    "towelhead", "trannie", "trannysaurus", "twatface", "twathead", "twatwaffle", "uncle tom",
    "vaginal", "wanker", "wetback", "wog", "wop", "zipperhead",

    // Historical / extreme (still attempted)
    "adolf", "aryan", "auschwitz", "faggotry", "heil", "kkk", "lynch", "mein kampf",
    "negroid", "reich", "sieghail", "skinhead", "ss", "swastica", "swastika", "white power",
    "wpww", "zog"
).sortedBy { it.length }