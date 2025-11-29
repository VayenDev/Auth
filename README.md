# Vayen Auth – Secure Session Backend

## What is Vayen Auth?

**Vayen Auth** is a secure, high-performance server application built on **Kotlin**. It is designed to provide a
dedicated,
standalone service for robust **account authentication** and **session management**.

Its primary function is to provide a secure Backend for:

* **Account Management:** Handling user registration and login.
* **Secure Password Storage:** Hashing and verifying passwords using **Argon2id**.
* **Session Management:** Creating and validating highly secure session tokens.
* **Session Security:** Signing session IDs using **HMAC SHA-256** with a per-session key.
* **Database Integration:** Integrating with a **PostgreSQL** database to persist account and session data.
* **High Performance:** Utilizing **Kache** for high-throughput in-memory caching of sessions and accounts.

It is ideal for applications that need a centralized, high-performance, and secure endpoint for all authentication and
session verification.

-----

## Features

* 🔒 **Secure Authentication:** Uses **Argon2id** for modern, memory-hard password hashing and verification.
* 🔐 **Secure Sessions:** Uses **HMAC SHA-256** for signing session IDs, ensuring tokens cannot be forged.
* ⚡ **High-Performance Caching:** Integrates **Kache** to provide a high-performance in-memory cache for sessions
  and accounts, minimizing the database load.
* 💾 **PostgreSQL Ready:** Uses the **Jetbrains Exposed** SQL ORM for seamless and fast integration with PostgreSQL.
* ⏱️ **Session Timeouts:** Configurable session durations with automatic validity checking and expiration.
* 🛡️ **TLS Support:** Can be configured to serve traffic over HTTPS for secure transport.

-----

## License

Vayen Auth is free software under the **GNU GPL v3**.
You can use it, modify it, and distribute it — as long as it remains free.