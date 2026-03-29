# FastAPI vs Robyn JWT API Comparison

This repository exists primarily to compare **the same small API implemented in both FastAPI and Robyn**.

The goal is not to build a feature-complete product. The goal is to keep the API surface small and comparable while testing:

- framework ergonomics
- Swagger/OpenAPI behavior
- JWT-based authentication
- database-backed login and authorization
- sync vs async endpoint handling
- operational differences between FastAPI and Robyn

## What Was Implemented

Both implementations now support a simple API backed by SQLite with:

- JWT bearer authentication
- database-driven user lookup
- password hashing
- role-based authorization
- public endpoints
- protected endpoints
- async protected endpoints
- admin-only user management endpoints

The same general behavior is implemented in:

- [fastapi_app.py](/Users/rupendrabandyopadhyay/Documents/Python_Apps/robyn_test/fastapi_app.py)
- [app.py](/Users/rupendrabandyopadhyay/Documents/Python_Apps/robyn_test/app.py)

## Why This Repo Exists

This project was built as a practical side-by-side comparison between:

- **FastAPI**
- **Robyn**

The working question behind the repo is:

> If you need a relatively small API with database-backed JWT authentication and role-based access, how do FastAPI and Robyn compare in implementation style, docs support, and overall developer experience?

That means the code intentionally includes the same kinds of concerns in both apps:

- login
- form login
- bearer auth
- protected routes
- role checks
- user CRUD-style admin endpoints
- password-change flows

## Project Structure

- [fastapi_app.py](/Users/rupendrabandyopadhyay/Documents/Python_Apps/robyn_test/fastapi_app.py)
  FastAPI implementation
- [app.py](/Users/rupendrabandyopadhyay/Documents/Python_Apps/robyn_test/app.py)
  Robyn implementation
- [db_setup.py](/Users/rupendrabandyopadhyay/Documents/Python_Apps/robyn_test/db_setup.py)
  SQLite schema/bootstrap script
- [db_crud.py](/Users/rupendrabandyopadhyay/Documents/Python_Apps/robyn_test/db_crud.py)
  shared CRUD and password-hashing helpers
- [create_user_cli.py](/Users/rupendrabandyopadhyay/Documents/Python_Apps/robyn_test/create_user_cli.py)
  command-line user creation helper
- [openapi.json](/Users/rupendrabandyopadhyay/Documents/Python_Apps/robyn_test/openapi.json)
  generated/customized OpenAPI spec used by the Robyn docs flow
- [docs.html](/Users/rupendrabandyopadhyay/Documents/Python_Apps/robyn_test/docs.html)
  custom Swagger page for Robyn

## Database Model

The SQLite database contains three tables:

- `user`
  - `user_id`
  - `user_email`
  - `password`
  - `is_active`
- `role`
  - `role_id`
  - `role_name`
- `user_role`
  - `user_id`
  - `role_id`

The database bootstrap script also seeds two roles:

- `USER`
- `ADMIN`

## Authentication Model

Authentication is now **database-backed** in both implementations.

That means:

- users are loaded from SQLite
- passwords are stored as salted PBKDF2 hashes
- login returns a bearer JWT-style token
- tokens include role information
- role checks are used for admin-only endpoints

For now, the token logic is intentionally lightweight and implemented directly in Python so the framework comparison stays easy to follow.

## Endpoints Implemented

### Public

- `GET /`
- `GET /health`
- `GET /async-health`

### Authentication

- `POST /authorize`
  accepts JSON with `user_email` and `password`
- `POST /authorize-form`
  accepts form fields with `user_email` and `password`
- `PUT /change-my-password`
  changes the password for the currently authenticated user

### Protected

- `GET /private`
- `GET /async-private-health`

### Admin Only

- `GET /users`
- `POST /users`
- `PUT /users/{user_email}`
- `PUT /users/{user_email}/change-password`
- `PUT /users/{user_email}/modify-roles`
- `DELETE /users/{user_email}`

In the Robyn app, the path parameter version is represented as `:user_email` in Python route declarations and appears as `{user_email}` in OpenAPI.

## Setup

Dependencies are managed with `uv`.

Install/update dependencies:

```bash
uv sync
```

Initialize the database:

```bash
uv run python db_setup.py
```

Create an initial admin user:

```bash
uv run python create_user_cli.py \
  --user-email admin@example.com \
  --password secret123 \
  --roles ADMIN
```

## Running FastAPI

You can run FastAPI directly:

```bash
uv run uvicorn fastapi_app:app --reload --port 9000
```

Or use the helper script:

```bash
./run_fastapi_app.sh
```

FastAPI docs:

```text
http://localhost:9000/docs
```

## Running Robyn

Run Robyn with the helper script:

```bash
./run_robyn_app.sh
```

Or specify a port:

```bash
./run_robyn_app.sh --port 8080
```

Robyn docs:

```text
http://localhost:8080/docs
```

## Comparison Focus

This repo is useful if you want to compare how FastAPI and Robyn differ in areas like:

- route definition style
- OpenAPI generation
- Swagger customization
- auth middleware patterns
- role-based authorization handling
- request parsing
- async endpoint ergonomics
- dependency setup and surrounding tooling

It is especially useful when evaluating a **small, performance-sensitive API** that still needs:

- authentication
- authorization
- database access
- user administration

## Feature Matrix

| Capability | FastAPI | Robyn |
| --- | --- | --- |
| Public endpoints | Yes | Yes |
| Async endpoints | Yes | Yes |
| DB-backed login | Yes | Yes |
| JWT bearer auth | Yes | Yes |
| Role-based authorization | Yes | Yes |
| JSON login endpoint | Yes | Yes |
| Form login endpoint | Yes | Yes |
| Self-service password change | Yes | Yes |
| Admin user management endpoints | Yes | Yes |
| Built-in docs flow | Native FastAPI docs | Custom docs page over Robyn OpenAPI |
| OpenAPI customization work | Lower | Higher |

## Notes

- This is still a demo/comparison project, not a production-ready auth system.
- `TOKEN_SECRET` is currently hardcoded in both apps and should be externalized.
- SQLite is used because it is simple for comparison and local testing.
- The Robyn app uses a custom `docs.html` because its built-in Swagger page was too rigid for the desired customizations.
- The FastAPI app uses native FastAPI docs generation.

## Suggested Next Steps

- move secrets to environment variables
- seed a default admin automatically in a controlled way
- add tests that hit both implementations with the same scenarios
- replace the handmade JWT logic with a maintained library
- add database migrations instead of recreating the DB
- benchmark both apps under the same workload
