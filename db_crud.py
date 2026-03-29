"""
This module provides CRUD operations for the User model using SQLAlchemy ORM.
It includes functions to create, update, deactivate, and retrieve users from
the database.

Example usage:

from db_crud import create_user, update_user, deactivate_user

user = create_user("alice@example.com", "secret123", ["USER"])
user = update_user(user["user_id"], role_names=["USER", "ADMIN"])
user = deactivate_user(user["user_id"])
"""
import hashlib
import hmac
import secrets
from typing import Any

from sqlalchemy import create_engine, delete, select
from sqlalchemy.orm import Session, sessionmaker

from db_setup import DATABASE_URL, Role, User, UserRole


engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
PASSWORD_ALGORITHM = "pbkdf2_sha256"
PASSWORD_ITERATIONS = 200_000


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    derived_key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        PASSWORD_ITERATIONS,
    )
    return f"{PASSWORD_ALGORITHM}${PASSWORD_ITERATIONS}${salt}${derived_key.hex()}"


def verify_password(password: str, password_hash: str) -> bool:
    try:
        algorithm, iterations_str, salt, stored_hash = password_hash.split("$", 3)
    except ValueError:
        return False

    if algorithm != PASSWORD_ALGORITHM:
        return False

    try:
        iterations = int(iterations_str)
    except ValueError:
        return False

    derived_key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        iterations,
    )
    return hmac.compare_digest(derived_key.hex(), stored_hash)


def _serialize_user(session: Session, user: User) -> dict[str, Any]:
    role_names = session.execute(
        select(Role.role_name)
        .join(UserRole, UserRole.role_id == Role.role_id)
        .where(UserRole.user_id == user.user_id)
        .order_by(Role.role_name)
    ).scalars().all()

    return {
        "user_id": user.user_id,
        "user_email": user.user_email,
        "password": user.password,
        "is_active": user.is_active,
        "roles": role_names,
    }


def _get_roles_by_name(session: Session, role_names: list[str]) -> list[Role]:
    roles = session.execute(
        select(Role).where(Role.role_name.in_(role_names))
    ).scalars().all()

    found_names = {role.role_name for role in roles}
    missing_names = sorted(set(role_names) - found_names)
    if missing_names:
        raise ValueError(f"Unknown role names: {', '.join(missing_names)}")

    return roles


def create_user(user_email: str, password: str, role_names: list[str], is_active: bool = True) -> dict[str, Any]:
    with SessionLocal() as session:
        existing_user = session.execute(
            select(User).where(User.user_email == user_email)
        ).scalar_one_or_none()
        if existing_user is not None:
            raise ValueError(f"User already exists with email: {user_email}")

        roles = _get_roles_by_name(session, role_names)

        user = User(
            user_email=user_email,
            password=hash_password(password),
            is_active=is_active,
        )
        session.add(user)
        session.flush()

        for role in roles:
            session.add(UserRole(user_id=user.user_id, role_id=role.role_id))

        session.commit()
        session.refresh(user)
        return _serialize_user(session, user)


def update_user(
    user_id: int,
    *,
    user_email: str | None = None,
    password: str | None = None,
    role_names: list[str] | None = None,
    is_active: bool | None = None,
) -> dict[str, Any]:
    with SessionLocal() as session:
        user = session.get(User, user_id)
        if user is None:
            raise ValueError(f"User not found: {user_id}")

        if user_email is not None and user_email != user.user_email:
            existing_user = session.execute(
                select(User).where(User.user_email == user_email)
            ).scalar_one_or_none()
            if existing_user is not None:
                raise ValueError(f"User already exists with email: {user_email}")
            user.user_email = user_email

        if password is not None:
            user.password = hash_password(password)

        if is_active is not None:
            user.is_active = is_active

        if role_names is not None:
            roles = _get_roles_by_name(session, role_names)
            session.execute(delete(UserRole).where(UserRole.user_id == user.user_id))
            session.flush()
            for role in roles:
                session.add(UserRole(user_id=user.user_id, role_id=role.role_id))

        session.commit()
        session.refresh(user)
        return _serialize_user(session, user)


def deactivate_user(user_id: int) -> dict[str, Any]:
    return update_user(user_id, is_active=False)


def get_user(user_id: int) -> dict[str, Any] | None:
    with SessionLocal() as session:
        user = session.get(User, user_id)
        if user is None:
            return None
        return _serialize_user(session, user)


def get_user_by_email(user_email: str) -> dict[str, Any] | None:
    with SessionLocal() as session:
        user = session.execute(
            select(User).where(User.user_email == user_email)
        ).scalar_one_or_none()
        if user is None:
            return None
        return _serialize_user(session, user)


def list_users() -> list[dict[str, Any]]:
    with SessionLocal() as session:
        users = session.execute(
            select(User).order_by(User.user_id)
        ).scalars().all()
        return [_serialize_user(session, user) for user in users]
