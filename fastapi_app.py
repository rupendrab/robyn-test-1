import asyncio
import base64
import hashlib
import hmac
import json
import time
from typing import Annotated

from fastapi import Depends, FastAPI, Form, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel


USERS = {
    "alice": "secret123",
    "bob": "password456",
}

TOKEN_SECRET = "change-me-in-production"
TOKEN_TTL_SECONDS = 3600


class AuthRequest(BaseModel):
    username: str
    password: str


class AuthResponse(BaseModel):
    access_token: str
    token_type: str
    expires_in: int


class PrivateResponse(BaseModel):
    message: str
    user: str


class AsyncHealthResponse(BaseModel):
    status: str
    mode: str


class AsyncPrivateResponse(BaseModel):
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


def authorize_user(username: str, password: str) -> AuthResponse:
    if USERS.get(username) != password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    return AuthResponse(
        access_token=generate_token(username),
        token_type="bearer",
        expires_in=TOKEN_TTL_SECONDS,
    )


bearer_scheme = HTTPBearer(auto_error=False)


def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
) -> str:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )

    username = verify_token(credentials.credentials)
    if username is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )

    return username


app = FastAPI(title="My API")


@app.get("/")
def home():
    return {"message": "FastAPI is running"}


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/async-health", response_model=AsyncHealthResponse)
async def async_health():
    await asyncio.sleep(0.1)
    return AsyncHealthResponse(status="ok", mode="async")


@app.post("/authorize", response_model=AuthResponse, tags=["Auth"])
def authorize(body: AuthRequest):
    return authorize_user(body.username, body.password)


@app.post("/authorize-form", response_model=AuthResponse, tags=["Auth"])
def authorize_form(
    username: Annotated[str, Form()],
    password: Annotated[str, Form(json_schema_extra={"format": "password"})],
):
    return authorize_user(username, password)


@app.get("/private", response_model=PrivateResponse, tags=["Auth"])
def private(user: Annotated[str, Depends(get_current_user)]):
    return PrivateResponse(message="Authenticated", user=user)


@app.get("/async-private-health", response_model=AsyncPrivateResponse, tags=["Auth"])
async def async_private_health(user: Annotated[str, Depends(get_current_user)]):
    await asyncio.sleep(0.1)
    return AsyncPrivateResponse(status="ok", mode="async", user=user)
