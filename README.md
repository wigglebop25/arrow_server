# ARROW Server

ARROW (**A**synchronous **R**ust **R**estaurant **O**rder **W**orkflow) Server is a high-performance, async-first REST API designed to modernize restaurant backend operations. Built with safety and concurrency at its core, it manages the full lifecycle of dining operations—from secure user authentication and role-based access control to inventory management and real-time order processing.

## Interesting Techniques

The codebase demonstrates several robust patterns for building scalable Rust applications:

*   **Repository Pattern with Generic Associated Types (GATs)**: The data layer is abstracted through a [`Repository` trait](./src/data/repos/traits/repository.rs) that leverages GATs (e.g., `type NewItem<'a>`). This allows for highly flexible implementations where lifetimes can be tied to specific operations, decoupled from the repository instance itself. [Learn more about GATs in Rust](https://blog.rust-lang.org/2022/10/28/gats-stabilization.html).
*   **Custom Axum Extractors for Auth**: Security is handled declaratively using [Axum's Extractor pattern](https://docs.rs/axum/latest/axum/extract/index.html). The [`AccessClaims` struct](./src/api/extractors.rs) implements `FromRequestParts`, automatically intercepting requests to validate JWT Bearer tokens and inject user identity into handlers, keeping business logic clean and focused.
*   **Lazy Static Connection Pooling**: Database connections are managed via a global, lazily-initialized pool using [`once_cell::sync::Lazy`](./src/data/database.rs). This ensures a single `deadpool` instance serves the entire application, minimizing overhead while maintaining thread safety.
*   **Asynchronous ORM with Diesel**: The project utilizes [`diesel-async`](https://crates.io/crates/diesel-async) to perform non-blocking SQL operations. It bridges the robust typing of Diesel with Tokio's async runtime, ensuring the server remains responsive even during heavy database load.

## Technologies & Libraries

This project integrates a suite of powerful libraries tailored for modern async Rust development:

*   **[Axum](https://crates.io/crates/axum)**: An ergonomic and modular web application framework that sits on top of Hyper.
*   **[Diesel Async](https://crates.io/crates/diesel-async)**: An extension to the Diesel ORM that adds fully asynchronous database interaction capabilities.
*   **[Tokio](https://crates.io/crates/tokio)**: The industry-standard asynchronous runtime for Rust, providing the event loop and I/O primitives.
*   **[Argon2](https://crates.io/crates/argon2)**: A prize-winning hashing algorithm used here for secure password storage.
*   **[Jsonwebtoken](https://crates.io/crates/jsonwebtoken)**: A robust implementation for creating and validating JSON Web Tokens (JWT).
*   **[Tracing](https://crates.io/crates/tracing)**: A framework for instrumenting Rust programs to collect structured, event-based diagnostic information.
*   **[Bigdecimal](https://crates.io/crates/bigdecimal)**: Arbitrary-precision decimal arithmetic, essential for handling currency without floating-point errors.

## Project Structure

```text
arrow_server/
├── .github/              # CI/CD workflows and Copilot instructions
├── bruno/                # API collection for testing endpoints (Bruno format)
├── src/
│   ├── api/
│   │   ├── controllers/  # Request handlers and DTOs
│   │   ├── routes/       # Endpoint definitions
│   │   ├── extractors.rs # Custom request parts extractors
│   │   └── server.rs     # Server configuration and startup
│   ├── data/
│   │   ├── migrations/   # SQL migration files
│   │   ├── models/       # Diesel structs (Schema definitions)
│   │   ├── repos/        # Repository implementations
│   │   └── database.rs   # Connection pool setup
│   ├── security/         # JWT and Auth logic
│   ├── services/         # Business logic layer
│   └── utils/            # Helper functions and mappers
└── tests/                # Integration tests for controllers and repos
```

**Directories of Note:**
*   `bruno/`: Contains a complete, pre-configured API collection for [Bruno](https://www.usebruno.com/), allowing for immediate testing of all endpoints.
*   `src/data/migrations/`: Stores the raw SQL migration files managed by Diesel, defining the evolution of the database schema.
*   `src/data/repos/`: Houses the concrete implementations of the repository traits, isolating the database logic from the rest of the application.
