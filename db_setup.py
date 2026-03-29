from pathlib import Path

from sqlalchemy import Boolean, ForeignKey, Integer, String, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column


DB_PATH = Path(__file__).with_name("auth.db")
DATABASE_URL = f"sqlite:///{DB_PATH}"


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "user"

    user_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_email: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    password: Mapped[str] = mapped_column(String, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)


class Role(Base):
    __tablename__ = "role"

    role_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    role_name: Mapped[str] = mapped_column(String, unique=True, nullable=False)


class UserRole(Base):
    __tablename__ = "user_role"

    user_id: Mapped[int] = mapped_column(ForeignKey("user.user_id"), primary_key=True)
    role_id: Mapped[int] = mapped_column(ForeignKey("role.role_id"), primary_key=True)


def create_database() -> None:
    if DB_PATH.exists():
        DB_PATH.unlink()

    engine = create_engine(DATABASE_URL)
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        for role_id, role_name in ((1, "USER"), (2, "ADMIN")):
            existing_role = session.get(Role, role_id)
            if existing_role is None:
                session.add(Role(role_id=role_id, role_name=role_name))
        session.commit()
    print(f"Created database at {DB_PATH}")


if __name__ == "__main__":
    create_database()
