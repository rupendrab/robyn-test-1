# Robyn Test App

This repository is a small Robyn API example that demonstrates:

- basic Robyn route setup
- synchronous and asynchronous endpoints
- JWT-style bearer authentication
- protected endpoints with `auth_required=True`
- Swagger/OpenAPI integration
- JSON and form-based login endpoints
- generating and overriding `openapi.json` so Swagger UI behaves correctly

## What This Project Shows

The app in [app.py](/Users/rupendrabandyopadhyay/Documents/Python_Apps/robyn_test/app.py) includes:

- public sync endpoints:
  - `GET /`
  - `GET /health`
- public async endpoint:
  - `GET /async-health`
- auth endpoints:
  - `POST /authorize` accepts JSON
  - `POST /authorize-form` accepts `application/x-www-form-urlencoded`
- protected endpoints:
  - `GET /private`
  - `GET /async-private-health`

Authentication is implemented with:

- an in-memory username/password dictionary
- a bearer token auth handler
- stateless HS256-signed JWT-like tokens with expiration
- OpenAPI bearer security metadata so Swagger's `Authorize` button works

## Why `openapi.json` Exists

Robyn can generate OpenAPI docs automatically, but this project also patches the generated spec so that:

- bearer auth appears correctly in Swagger UI
- protected endpoints are marked with `security`
- the form-based auth endpoint renders form fields instead of a JSON body

That generated spec is written to [openapi.json](/Users/rupendrabandyopadhyay/Documents/Python_Apps/robyn_test/openapi.json) and then served by Robyn.

## Requirements

- Python 3.12+
- Robyn `0.82.x`

Dependencies are defined in [pyproject.toml](/Users/rupendrabandyopadhyay/Documents/Python_Apps/robyn_test/pyproject.toml).

## Running The App

If you are using the local virtual environment:

```bash
.venv/bin/python app.py
```

Or with a standard Python environment:

```bash
python app.py
```

The app starts on:

```text
http://localhost:8080
```

Swagger UI is available at:

```text
http://localhost:8080/docs
```

OpenAPI JSON is available at:

```text
http://localhost:8080/openapi.json
```

## Example Credentials

The demo users are currently hardcoded in [app.py](/Users/rupendrabandyopadhyay/Documents/Python_Apps/robyn_test/app.py):

- `alice / secret123`
- `bob / password456`

## Example Requests

JSON login:

```bash
curl -X POST \
  http://localhost:8080/authorize \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"secret123"}'
```

Form login:

```bash
curl -X POST \
  http://localhost:8080/authorize-form \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'username=alice&password=secret123'
```

Protected endpoint:

```bash
curl -X GET \
  http://localhost:8080/private \
  -H 'Authorization: Bearer <token>'
```

Protected async endpoint:

```bash
curl -X GET \
  http://localhost:8080/async-private-health \
  -H 'Authorization: Bearer <token>'
```

## Notes

- This is a demonstration project, not a production auth implementation.
- `TOKEN_SECRET` is currently hardcoded and should be moved to an environment variable.
- Passwords are stored in plaintext for simplicity.
- The token format is signed and time-limited, but there is no refresh or revocation flow.

## Suggested Next Steps

- move secrets and users into environment variables or a database
- hash passwords with a proper password hashing library
- replace the homemade JWT logic with a maintained JWT library
- add refresh tokens or token revocation if session management is needed
- add tests for auth success, auth failure, and token expiration
