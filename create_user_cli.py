"""
This script provides a command-line interface (CLI) to create a user in the auth database.
It uses the create_user function from the db_crud module to perform the database
operation.

Example usage:
python create_user_cli.py --user-email admin@example.com --password secret123 --roles ADMIN USER
"""
import argparse

from db_crud import create_user


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Create a user in the auth database.")
    parser.add_argument("--user-email", required=True, help="User email address")
    parser.add_argument("--password", required=True, help="User password")
    parser.add_argument(
        "--roles",
        required=True,
        nargs="+",
        help="One or more role names, for example: ADMIN USER",
    )
    parser.add_argument(
        "--inactive",
        action="store_true",
        help="Create the user as inactive",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    created_user = create_user(
        user_email=args.user_email,
        password=args.password,
        role_names=args.roles,
        is_active=not args.inactive,
    )

    print("Created user:")
    print(f"  user_id: {created_user['user_id']}")
    print(f"  user_email: {created_user['user_email']}")
    print(f"  is_active: {created_user['is_active']}")
    print(f"  roles: {', '.join(created_user['roles'])}")


if __name__ == "__main__":
    main()
