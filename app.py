import base64
import asyncio
import hashlib
import hmac
import json
import time
from pathlib import Path
from typing import TypedDict

from robyn import OpenAPI, Robyn
from robyn.authentication import AuthenticationHandler, BearerGetter
from robyn.openapi import OpenAPIInfo
from robyn.robyn import Identity, Request, Response
from robyn.status_codes import HTTP_401_UNAUTHORIZED


USERS = {
    "alice": "secret123",
    "bob": "password456",
}

TOKEN_SECRET = "change-me-in-production"
TOKEN_TTL_SECONDS = 3600
OPENAPI_SPEC_PATH = Path(__file__).with_name("openapi.json")
OPENAPI_INFO = OpenAPIInfo(
    title="My API",
    version="1.0.0",
    description="A simple API built with Robyn",
)


class AuthRequest(TypedDict):
    username: str
    password: str


class AuthResponse(TypedDict):
    access_token: str
    token_type: str
    expires_in: int


class PrivateResponse(TypedDict):
    message: str
    user: str


class AsyncPrivateResponse(TypedDict):
    status: str
    mode: str
    user: str


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def generate_token(username: str) -> str:
    now = int(time.time())
    header = {
        "alg": "HS256",
        "typ": "JWT",
    }
    payload = {
        "sub": username,
        "iat": now,
        "exp": now + TOKEN_TTL_SECONDS,
    }
    header_part = _b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_part = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{header_part}.{payload_part}"
    signature = hmac.new(TOKEN_SECRET.encode("utf-8"), signing_input.encode("utf-8"), hashlib.sha256).digest()
    signature_part = _b64url_encode(signature)
    return f"{header_part}.{payload_part}.{signature_part}"


def verify_token(token: str) -> str | None:
    try:
        header_part, payload_part, signature_part = token.split(".", 2)
    except ValueError:
        return None

    try:
        header = json.loads(_b64url_decode(header_part).decode("utf-8"))
        payload = json.loads(_b64url_decode(payload_part).decode("utf-8"))
        actual_signature = _b64url_decode(signature_part)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
        return None

    if header.get("alg") != "HS256" or header.get("typ") != "JWT":
        return None

    signing_input = f"{header_part}.{payload_part}"
    expected_signature = hmac.new(TOKEN_SECRET.encode("utf-8"), signing_input.encode("utf-8"), hashlib.sha256).digest()

    if not hmac.compare_digest(actual_signature, expected_signature):
        return None

    if payload.get("exp", 0) < int(time.time()):
        return None

    username = payload.get("sub")
    if not isinstance(username, str):
        return None

    return username


class DictionaryBearerAuthHandler(AuthenticationHandler):
    def authenticate(self, request: Request) -> Identity | None:
        token = self.token_getter.get_token(request)
        if token is None:
            return None

        username = verify_token(token)
        if username is None:
            return None

        return Identity(claims={"sub": username})


app = Robyn(
    __file__,
    openapi=OpenAPI(info=OPENAPI_INFO),
)

app.configure_authentication(DictionaryBearerAuthHandler(token_getter=BearerGetter()))


@app.get("/", openapi_name="Get Root", openapi_tags=["General"])
def home():
    return {"message": "Robyn API is running"}


@app.get("/health", openapi_name="Get Health Status", openapi_tags=["General"])
def health():
    return {"status": "ok"}


@app.get("/async-health", openapi_name="Get Async Health Status", openapi_tags=["General"])
async def async_health():
    await asyncio.sleep(0.1)
    return {"status": "ok", "mode": "async"}


@app.get("/async-private-health", auth_required=True, openapi_name="Get Async Private Health Status", openapi_tags=["Auth"])
async def async_private_health(request: Request) -> AsyncPrivateResponse:
    await asyncio.sleep(0.1)
    return {
        "status": "ok",
        "mode": "async",
        "user": request.identity.claims["sub"],
    }


@app.post("/authorize", openapi_name="Authorize User", openapi_tags=["Auth"])
def authorize(body: AuthRequest) -> AuthResponse | Response:
    username = body["username"]
    password = body["password"]

    if USERS.get(username) != password:
        return Response(
            status_code=HTTP_401_UNAUTHORIZED,
            headers={"Content-Type": "application/json"},
            description='{"error":"Invalid username or password"}',
        )

    token = generate_token(username)

    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": TOKEN_TTL_SECONDS,
    }


@app.get("/private", auth_required=True, openapi_name="Get Private Route", openapi_tags=["Auth"])
def private(request: Request) -> PrivateResponse:
    return {
        "message": "Authenticated",
        "user": request.identity.claims["sub"],
    }


def configure_openapi_security():
    spec = app.openapi.openapi_spec
    components = spec.setdefault("components", {})
    security_schemes = components.setdefault("securitySchemes", {})
    security_schemes["BearerAuth"] = {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "JWT",
    }

    private_get = spec.get("paths", {}).get("/private", {}).get("get")
    if private_get is not None:
        private_get["security"] = [{"BearerAuth": []}]

    async_private_get = spec.get("paths", {}).get("/async-private-health", {}).get("get")
    if async_private_get is not None:
        async_private_get["security"] = [{"BearerAuth": []}]


def generate_openapi_spec():
    generated_openapi = OpenAPI(info=OPENAPI_INFO)
    app.router.prepare_routes_openapi(generated_openapi, app.included_routers)
    app.openapi = generated_openapi
    configure_openapi_security()
    with OPENAPI_SPEC_PATH.open("w", encoding="utf-8") as spec_file:
        json.dump(app.openapi.openapi_spec, spec_file, indent=2)
    app.openapi.override_openapi(OPENAPI_SPEC_PATH)


generate_openapi_spec()


if __name__ == "__main__":
    app.start(host="0.0.0.0", port=8080)
