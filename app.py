import argparse
import asyncio
import base64
import hashlib
import hmac
import json
import time
from pathlib import Path
from urllib.parse import parse_qs
from typing import TypedDict

from robyn import OpenAPI, Robyn
from robyn.argument_parser import Config
from robyn.authentication import AuthenticationHandler, BearerGetter
from robyn.openapi import OpenAPIInfo
from robyn.responses import serve_html
from robyn.robyn import Headers, Identity, Request, Response
from robyn.status_codes import HTTP_401_UNAUTHORIZED, HTTP_403_FORBIDDEN, HTTP_404_NOT_FOUND

from db_crud import create_user as db_create_user
from db_crud import deactivate_user as db_deactivate_user
from db_crud import get_user_by_email as db_get_user_by_email
from db_crud import list_users as db_list_users
from db_crud import update_user as db_update_user
from db_crud import verify_password


TOKEN_SECRET = "change-me-in-production"
TOKEN_TTL_SECONDS = 3600
OPENAPI_SPEC_PATH = Path(__file__).with_name("openapi.json")
DOCS_HTML_PATH = Path(__file__).with_name("docs.html")
OPENAPI_INFO = OpenAPIInfo(
    title="My API",
    version="1.0.0",
    description="A simple API built with Robyn",
)
APP_CONFIG = Config()
APP_CONFIG.disable_openapi = True


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--port", type=int, default=8080)
    args, _ = parser.parse_known_args()
    return args


class AuthRequest(TypedDict):
    user_email: str
    password: str


class AuthResponse(TypedDict):
    access_token: str
    token_type: str
    expires_in: int


class PrivateResponse(TypedDict):
    message: str
    user: str


class AsyncHealthResponse(TypedDict):
    status: str
    mode: str


class AsyncPrivateResponse(TypedDict):
    status: str
    mode: str
    user: str


class UserCreateRequest(TypedDict):
    user_email: str
    password: str
    role_names: list[str]
    is_active: bool


class UserResponse(TypedDict):
    user_id: int
    user_email: str
    is_active: bool
    roles: list[str]


class UserUpdateRequest(TypedDict):
    password: str
    role_names: list[str]
    is_active: bool


class ChangePasswordRequest(TypedDict):
    password: str


class ModifyRolesRequest(TypedDict):
    role_names: list[str]


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def generate_token(user_email: str, roles: list[str]) -> str:
    now = int(time.time())
    header = {"alg": "HS256", "typ": "JWT"}
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

    return {"user_email": user_email, "roles": roles}


def json_error(status_code: int, message: str) -> Response:
    return Response(
        status_code=status_code,
        headers=Headers({"Content-Type": "application/json"}),
        description=json.dumps({"error": message}),
    )


def serialize_user_output(user: dict) -> UserResponse:
    return {
        "user_id": user["user_id"],
        "user_email": user["user_email"],
        "is_active": user["is_active"],
        "roles": user["roles"],
    }


def authorize_user(user_email: str, password: str) -> AuthResponse | Response:
    user = db_get_user_by_email(user_email)
    if user is None or not user["is_active"] or not verify_password(password, user["password"]):
        return json_error(HTTP_401_UNAUTHORIZED, "Invalid email or password")

    return {
        "access_token": generate_token(user["user_email"], user["roles"]),
        "token_type": "bearer",
        "expires_in": TOKEN_TTL_SECONDS,
    }


def get_request_user_email(request: Request) -> str:
    return request.identity.claims["sub"]


def get_request_user_roles(request: Request) -> list[str]:
    roles_value = request.identity.claims.get("roles", "")
    return [role for role in roles_value.split(",") if role]


def require_role(request: Request, role_name: str) -> Response | None:
    if role_name not in get_request_user_roles(request):
        return json_error(HTTP_403_FORBIDDEN, "Insufficient permissions")
    return None


class DatabaseBearerAuthHandler(AuthenticationHandler):
    def authenticate(self, request: Request) -> Identity | None:
        token = self.token_getter.get_token(request)
        if token is None:
            return None

        token_payload = verify_token(token)
        if token_payload is None:
            return None

        db_user = db_get_user_by_email(token_payload["user_email"])
        if db_user is None or not db_user["is_active"]:
            return None

        return Identity(
            claims={
                "sub": db_user["user_email"],
                "roles": ",".join(db_user["roles"]),
            }
        )


app = Robyn(
    __file__,
    config=APP_CONFIG,
    openapi=OpenAPI(info=OPENAPI_INFO),
)

app.configure_authentication(DatabaseBearerAuthHandler(token_getter=BearerGetter()))


@app.get("/", openapi_name="Get Root", openapi_tags=["General"])
def home():
    return {"message": "Robyn API is running"}


@app.get("/health", openapi_name="Get Health Status", openapi_tags=["General"])
def health():
    return {"status": "ok"}


@app.get("/docs", const=True, openapi_name="Get API Docs", openapi_tags=["General"])
def docs():
    return serve_html(str(DOCS_HTML_PATH))


@app.get("/openapi.json", const=True, openapi_name="Get OpenAPI Spec", openapi_tags=["General"])
def openapi_spec():
    return app.openapi.get_openapi_config()


@app.get("/async-health", openapi_name="Get Async Health Status", openapi_tags=["General"])
async def async_health() -> AsyncHealthResponse:
    await asyncio.sleep(0.1)
    return {"status": "ok", "mode": "async"}


@app.post("/authorize", openapi_name="Authorize User", openapi_tags=["Auth"])
def authorize(body: AuthRequest) -> AuthResponse | Response:
    return authorize_user(body["user_email"], body["password"])


@app.post("/authorize-form", openapi_name="Authorize User With Form", openapi_tags=["Auth"])
def authorize_form(request: Request) -> AuthResponse | Response:
    raw_body = request.body.decode("utf-8") if isinstance(request.body, bytes) else str(request.body)
    parsed_form = parse_qs(raw_body)
    user_email = parsed_form.get("user_email", [""])[0]
    password = parsed_form.get("password", [""])[0]
    return authorize_user(user_email, password)


@app.get("/private", auth_required=True, openapi_name="Get Private Route", openapi_tags=["Auth"])
def private(request: Request) -> PrivateResponse:
    return {
        "message": "Authenticated",
        "user": get_request_user_email(request),
    }


@app.get("/async-private-health", auth_required=True, openapi_name="Get Async Private Health Status", openapi_tags=["Auth"])
async def async_private_health(request: Request) -> AsyncPrivateResponse:
    await asyncio.sleep(0.1)
    return {
        "status": "ok",
        "mode": "async",
        "user": get_request_user_email(request),
    }


@app.put("/change-my-password", auth_required=True, openapi_name="Change My Password", openapi_tags=["Auth"])
def change_my_password(request: Request, body: ChangePasswordRequest) -> UserResponse | Response:
    db_user = db_get_user_by_email(get_request_user_email(request))
    if db_user is None:
        return json_error(HTTP_404_NOT_FOUND, "User not found")

    try:
        updated_user = db_update_user(db_user["user_id"], password=body["password"])
    except ValueError as exc:
        return json_error(HTTP_401_UNAUTHORIZED, str(exc))

    return serialize_user_output(updated_user)


@app.get("/users", auth_required=True, openapi_name="List Users", openapi_tags=["Users"])
def list_users(request: Request) -> list[UserResponse] | Response:
    forbidden = require_role(request, "ADMIN")
    if forbidden is not None:
        return forbidden
    return [serialize_user_output(user) for user in db_list_users()]


@app.post("/users", auth_required=True, openapi_name="Create User", openapi_tags=["Users"])
def create_user(request: Request, body: UserCreateRequest) -> UserResponse | Response:
    forbidden = require_role(request, "ADMIN")
    if forbidden is not None:
        return forbidden

    try:
        created_user = db_create_user(
            user_email=body["user_email"],
            password=body["password"],
            role_names=body["role_names"],
            is_active=body["is_active"],
        )
    except ValueError as exc:
        return json_error(HTTP_401_UNAUTHORIZED, str(exc))

    return serialize_user_output(created_user)


@app.put("/users/:user_email", auth_required=True, openapi_name="Update User", openapi_tags=["Users"])
def update_user(request: Request, user_email: str, body: UserUpdateRequest) -> UserResponse | Response:
    forbidden = require_role(request, "ADMIN")
    if forbidden is not None:
        return forbidden

    existing_user = db_get_user_by_email(user_email)
    if existing_user is None:
        return json_error(HTTP_404_NOT_FOUND, f"User not found: {user_email}")

    try:
        updated_user = db_update_user(
            existing_user["user_id"],
            password=body.get("password"),
            role_names=body.get("role_names"),
            is_active=body.get("is_active"),
        )
    except ValueError as exc:
        return json_error(HTTP_401_UNAUTHORIZED, str(exc))

    return serialize_user_output(updated_user)


@app.put("/users/:user_email/change-password", auth_required=True, openapi_name="Change User Password", openapi_tags=["Users"])
def change_user_password(request: Request, user_email: str, body: ChangePasswordRequest) -> UserResponse | Response:
    forbidden = require_role(request, "ADMIN")
    if forbidden is not None:
        return forbidden

    existing_user = db_get_user_by_email(user_email)
    if existing_user is None:
        return json_error(HTTP_404_NOT_FOUND, f"User not found: {user_email}")

    updated_user = db_update_user(existing_user["user_id"], password=body["password"])
    return serialize_user_output(updated_user)


@app.put("/users/:user_email/modify-roles", auth_required=True, openapi_name="Modify User Roles", openapi_tags=["Users"])
def modify_user_roles(request: Request, user_email: str, body: ModifyRolesRequest) -> UserResponse | Response:
    forbidden = require_role(request, "ADMIN")
    if forbidden is not None:
        return forbidden

    existing_user = db_get_user_by_email(user_email)
    if existing_user is None:
        return json_error(HTTP_404_NOT_FOUND, f"User not found: {user_email}")

    try:
        updated_user = db_update_user(existing_user["user_id"], role_names=body["role_names"])
    except ValueError as exc:
        return json_error(HTTP_401_UNAUTHORIZED, str(exc))

    return serialize_user_output(updated_user)


@app.delete("/users/:user_email", auth_required=True, openapi_name="Delete User", openapi_tags=["Users"])
def delete_user(request: Request, user_email: str) -> UserResponse | Response:
    forbidden = require_role(request, "ADMIN")
    if forbidden is not None:
        return forbidden

    existing_user = db_get_user_by_email(user_email)
    if existing_user is None:
        return json_error(HTTP_404_NOT_FOUND, f"User not found: {user_email}")

    updated_user = db_deactivate_user(existing_user["user_id"])
    return serialize_user_output(updated_user)


def configure_openapi_security():
    spec = app.openapi.openapi_spec
    components = spec.setdefault("components", {})
    security_schemes = components.setdefault("securitySchemes", {})
    security_schemes["BearerAuth"] = {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "JWT",
    }

    secured_operations = [
        ("/private", "get"),
        ("/async-private-health", "get"),
        ("/change-my-password", "put"),
        ("/users", "get"),
        ("/users", "post"),
        ("/users/{user_email}", "put"),
        ("/users/{user_email}/change-password", "put"),
        ("/users/{user_email}/modify-roles", "put"),
        ("/users/{user_email}", "delete"),
    ]

    for path, method in secured_operations:
        operation = spec.get("paths", {}).get(path, {}).get(method)
        if operation is not None:
            operation["security"] = [{"BearerAuth": []}]

    authorize_form_post = spec.get("paths", {}).get("/authorize-form", {}).get("post")
    if authorize_form_post is not None:
        authorize_form_post["requestBody"] = {
            "required": True,
            "content": {
                "application/x-www-form-urlencoded": {
                    "schema": {
                        "type": "object",
                        "properties": {
                            "user_email": {"type": "string"},
                            "password": {"type": "string", "format": "password"},
                        },
                        "required": ["user_email", "password"],
                    }
                }
            },
        }


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
    args = parse_args()
    app.start(host="0.0.0.0", port=args.port)
