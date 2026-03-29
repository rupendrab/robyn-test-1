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

from db_crud import create_user as db_create_user
from db_crud import deactivate_user as db_deactivate_user
from db_crud import get_user_by_email as db_get_user_by_email
from db_crud import list_users as db_list_users
from db_crud import update_user as db_update_user
from db_crud import verify_password

TOKEN_SECRET = "change-me-in-production"
TOKEN_TTL_SECONDS = 3600


class AuthRequest(BaseModel):
    user_email: str
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


class CurrentUser(BaseModel):
    user_id: int | None = None
    user_email: str
    roles: list[str]


class UserCreateRequest(BaseModel):
    user_email: str
    password: str
    role_names: list[str]
    is_active: bool = True


class UserResponse(BaseModel):
    user_id: int
    user_email: str
    is_active: bool
    roles: list[str]


class UserUpdateRequest(BaseModel):
    password: str | None = None
    role_names: list[str] | None = None
    is_active: bool | None = None


class ChangePasswordRequest(BaseModel):
    password: str


class ModifyRolesRequest(BaseModel):
    role_names: list[str]


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def generate_token(user_email: str, roles: list[str]) -> str:
    now = int(time.time())
    header = {
        "alg": "HS256",
        "typ": "JWT",
    }
    payload = {
        "sub": user_email,
        "roles": roles,
        "iat": now,
        "exp": now + TOKEN_TTL_SECONDS,
    }
    header_part = _b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_part = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{header_part}.{payload_part}"
    signature = hmac.new(TOKEN_SECRET.encode("utf-8"), signing_input.encode("utf-8"), hashlib.sha256).digest()
    signature_part = _b64url_encode(signature)
    return f"{header_part}.{payload_part}.{signature_part}"


def verify_token(token: str) -> dict | None:
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

    user_email = payload.get("sub")
    roles = payload.get("roles", [])
    if not isinstance(user_email, str):
        return None
    if not isinstance(roles, list) or not all(isinstance(role, str) for role in roles):
        return None

    return {
        "user_email": user_email,
        "roles": roles,
    }


def authorize_user(user_email: str, password: str) -> AuthResponse:
    user = db_get_user_by_email(user_email)
    if user is None or not user["is_active"] or not verify_password(password, user["password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    return AuthResponse(
        access_token=generate_token(user["user_email"], user["roles"]),
        token_type="bearer",
        expires_in=TOKEN_TTL_SECONDS,
    )


bearer_scheme = HTTPBearer(auto_error=False)


def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
) -> CurrentUser:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )

    token_payload = verify_token(credentials.credentials)
    if token_payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )

    db_user = db_get_user_by_email(token_payload["user_email"])
    if db_user is None or not db_user["is_active"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User is not active",
        )

    return CurrentUser(
        user_id=db_user["user_id"],
        user_email=db_user["user_email"],
        roles=db_user["roles"],
    )


def require_roles(*required_roles: str):
    def dependency(current_user: Annotated[CurrentUser, Depends(get_current_user)]) -> CurrentUser:
        if not any(role in current_user.roles for role in required_roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )
        return current_user

    return dependency


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
    return authorize_user(body.user_email, body.password)


@app.post("/authorize-form", response_model=AuthResponse, tags=["Auth"])
def authorize_form(
    user_email: Annotated[str, Form()],
    password: Annotated[str, Form(json_schema_extra={"format": "password"})],
):
    return authorize_user(user_email, password)


@app.get("/private", response_model=PrivateResponse, tags=["Auth"])
def private(current_user: Annotated[CurrentUser, Depends(get_current_user)]):
    return PrivateResponse(message="Authenticated", user=current_user.user_email)


@app.get("/async-private-health", response_model=AsyncPrivateResponse, tags=["Auth"])
async def async_private_health(current_user: Annotated[CurrentUser, Depends(get_current_user)]):
    await asyncio.sleep(0.1)
    return AsyncPrivateResponse(status="ok", mode="async", user=current_user.user_email)


@app.put("/change-my-password", response_model=UserResponse, tags=["Auth"], summary="Change My Password")
def change_my_password(
    body: ChangePasswordRequest,
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
):
    try:
        updated_user = db_update_user(
            current_user.user_id,
            password=body.password,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    return UserResponse(
        user_id=updated_user["user_id"],
        user_email=updated_user["user_email"],
        is_active=updated_user["is_active"],
        roles=updated_user["roles"],
    )


@app.put("/users/{user_email}/change-password", response_model=UserResponse, tags=["Users"], summary="Change User Password")
def change_user_password(
    user_email: str,
    body: ChangePasswordRequest,
    _: Annotated[CurrentUser, Depends(require_roles("ADMIN"))],
):
    existing_user = db_get_user_by_email(user_email)
    if existing_user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User not found: {user_email}",
        )

    try:
        updated_user = db_update_user(
            existing_user["user_id"],
            password=body.password,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    return UserResponse(
        user_id=updated_user["user_id"],
        user_email=updated_user["user_email"],
        is_active=updated_user["is_active"],
        roles=updated_user["roles"],
    )


@app.put("/users/{user_email}/modify-roles", response_model=UserResponse, tags=["Users"], summary="Modify User Roles")
def modify_user_roles(
    user_email: str,
    body: ModifyRolesRequest,
    _: Annotated[CurrentUser, Depends(require_roles("ADMIN"))],
):
    existing_user = db_get_user_by_email(user_email)
    if existing_user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User not found: {user_email}",
        )

    try:
        updated_user = db_update_user(
            existing_user["user_id"],
            role_names=body.role_names,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    return UserResponse(
        user_id=updated_user["user_id"],
        user_email=updated_user["user_email"],
        is_active=updated_user["is_active"],
        roles=updated_user["roles"],
    )


@app.delete("/users/{user_email}", response_model=UserResponse, tags=["Users"], summary="Delete User")
def delete_user(
    user_email: str,
    _: Annotated[CurrentUser, Depends(require_roles("ADMIN"))],
):
    existing_user = db_get_user_by_email(user_email)
    if existing_user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User not found: {user_email}",
        )

    try:
        updated_user = db_deactivate_user(existing_user["user_id"])
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    return UserResponse(
        user_id=updated_user["user_id"],
        user_email=updated_user["user_email"],
        is_active=updated_user["is_active"],
        roles=updated_user["roles"],
    )


@app.get("/users", response_model=list[UserResponse], tags=["Users"], summary="List Users")
def list_db_users(
    _: Annotated[CurrentUser, Depends(require_roles("ADMIN"))],
):
    users = db_list_users()
    return [
        UserResponse(
            user_id=user["user_id"],
            user_email=user["user_email"],
            is_active=user["is_active"],
            roles=user["roles"],
        )
        for user in users
    ]


@app.post("/users", response_model=UserResponse, tags=["Users"], summary="Create User")
def create_db_user(
    body: UserCreateRequest,
    _: Annotated[CurrentUser, Depends(require_roles("ADMIN"))],
):
    try:
        created_user = db_create_user(
            user_email=body.user_email,
            password=body.password,
            role_names=body.role_names,
            is_active=body.is_active,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    return UserResponse(
        user_id=created_user["user_id"],
        user_email=created_user["user_email"],
        is_active=created_user["is_active"],
        roles=created_user["roles"],
    )


@app.put("/users/{user_email}", response_model=UserResponse, tags=["Users"], summary="Update User")
def update_db_user(
    user_email: str,
    body: UserUpdateRequest,
    _: Annotated[CurrentUser, Depends(require_roles("ADMIN"))],
):
    existing_user = db_get_user_by_email(user_email)
    if existing_user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User not found: {user_email}",
        )

    try:
        updated_user = db_update_user(
            existing_user["user_id"],
            password=body.password,
            role_names=body.role_names,
            is_active=body.is_active,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    return UserResponse(
        user_id=updated_user["user_id"],
        user_email=updated_user["user_email"],
        is_active=updated_user["is_active"],
        roles=updated_user["roles"],
    )
