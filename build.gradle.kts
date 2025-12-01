/*
 * Vayen Auth (Vayen_Auth): build.gradle.kts
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

val exposedVersion = "0.61.0"
val h2Version = "2.3.232"
val kotlinVersion = "2.2.20"
val ktorVersion = "3.3.2"
val postgresVersion = "42.7.8"

plugins {
    kotlin("jvm") version "2.2.20"
    id("io.ktor.plugin") version "3.3.2"
    id("org.jetbrains.kotlin.plugin.serialization") version "2.2.20"
}

group = "dev.vayen"
version = "0.0.1"

application {
    mainClass = "dev.vayen.ApplicationKt"
}

repositories {
    mavenCentral()
    maven {
        url = uri("https://packages.confluent.io/maven")
        name = "confluence"
    }
}

dependencies {
    implementation("io.github.flaxoos:ktor-server-rate-limiting:2.2.1")
    implementation("io.ktor:ktor-server-core")
    implementation("io.ktor:ktor-server-content-negotiation")
    implementation("io.ktor:ktor-serialization-kotlinx-json")
    implementation("org.jetbrains.exposed:exposed-core:$exposedVersion")
    implementation("org.jetbrains.exposed:exposed-jdbc:$exposedVersion")
    implementation("org.jetbrains.exposed:exposed-kotlin-datetime:${exposedVersion}")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.9.0")
    implementation("org.postgresql:postgresql:$postgresVersion")
    implementation("io.ktor:ktor-server-call-id")
    implementation("io.ktor:ktor-server-resources")
    implementation("io.ktor:ktor-server-csrf")
    implementation("io.ktor:ktor-server-hsts")
    implementation("io.ktor:ktor-server-http-redirect")
    implementation("io.ktor:ktor-server-cors")
    implementation("io.ktor:ktor-server-cio")
    implementation("dev.mtctx.library:lumina:4.1.1")
    implementation("dev.mtctx.library:utilities:1.7.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.10.2")
    implementation("com.mayakapps.kache:kache:2.1.1")
    implementation("com.webauthn4j:webauthn4j-core:0.30.0.RELEASE")
    implementation("io.ktor:ktor-server-forwarded-header:3.3.2")
    implementation("io.ktor:ktor-server-default-headers:3.3.2")
    implementation("io.github.flaxoos:ktor-client-circuit-breaker:2.2.1")
    implementation("io.ktor:ktor-server-sessions:3.3.2")
    implementation("io.ktor:ktor-server-call-logging:3.3.2")
    implementation("io.ktor:ktor-server-call-logging:3.3.2")

    testImplementation("io.ktor:ktor-server-test-host")
    testImplementation("org.jetbrains.kotlin:kotlin-test-junit:$kotlinVersion")
}