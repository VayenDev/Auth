# Vayen Auth – Secure Session Backend

## What is Vayen Auth-Backend?

**Vayen Auth** is a secure, server application built on **Go** designed to handle robust and extensible **session management**.

Its primary function is to provide a dedicated, secure service for:

* **Creating** and **validating** highly secure session IDs using **Argon2** hashing.
* Integrating with a **PostgreSQL** database to persist session data.
* Offering an **extensible plugin system** to customize and add new features via external JARs.

It is ideal for applications that need a centralized, high-performance, and pluggable authentication and session
verification endpoint.

-----

## Features

* 🔒 **Secure Sessions:** Uses **Argon2** for hashing session IDs with a per-session salt, ensuring robust security.
* ⏱️ **Session Timeouts:** Configurable session durations with automatic validity checking.
* 💾 **PostgreSQL Ready:** Uses the **pgx** SQL framework for seamless integration with PostgreSQL.

-----

## License

ReAuth-Backend is free software under the **GNU GPL v3**.
You can use it, modify it, and distribute it — as long as it remains free.