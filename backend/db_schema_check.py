"""
Detect SQLAlchemy/PostgreSQL schema mismatches and optionally apply additive fixes.

Usage:
    python backend/db_schema_check.py
    python backend/db_schema_check.py --apply
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
import sys

from sqlalchemy import inspect, text

CURRENT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(CURRENT_DIR))

from database import engine  # noqa: E402
from models import Base  # noqa: E402,F401


@dataclass(frozen=True)
class MissingColumn:
    table_name: str
    column_name: str
    sql_type: str
    nullable_sql: str
    default_sql: str

    @property
    def alter_sql(self) -> str:
        return (
            f"ALTER TABLE {self.table_name} "
            f"ADD COLUMN IF NOT EXISTS {self.column_name} "
            f"{self.sql_type}{self.default_sql}{self.nullable_sql};"
        )


def compile_type(column) -> str:
    return column.type.compile(dialect=engine.dialect)


def column_default_sql(table_name: str, column) -> str:
    if table_name == "users" and column.name == "failed_login_attempts":
        return " DEFAULT 0"
    if table_name == "users" and column.name == "otp_attempts":
        return " DEFAULT 0"
    if table_name == "users" and column.name == "usage_count":
        return " DEFAULT 0"
    return ""


def detect_missing_columns() -> list[MissingColumn]:
    inspector = inspect(engine)
    existing_tables = set(inspector.get_table_names())
    missing: list[MissingColumn] = []

    for table in Base.metadata.sorted_tables:
        if table.name not in existing_tables:
            continue

        existing_columns = {column["name"] for column in inspector.get_columns(table.name)}
        for column in table.columns:
            if column.name in existing_columns:
                continue

            missing.append(
                MissingColumn(
                    table_name=table.name,
                    column_name=column.name,
                    sql_type=compile_type(column),
                    nullable_sql="" if column.nullable else " NOT NULL",
                    default_sql=column_default_sql(table.name, column),
                )
            )

    return missing


def apply_missing_columns(missing: list[MissingColumn]) -> None:
    with engine.begin() as connection:
        for item in missing:
            connection.execute(text(item.alter_sql))
        connection.execute(
            text("UPDATE users SET failed_login_attempts = 0 WHERE failed_login_attempts IS NULL")
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true", help="Apply additive ALTER TABLE statements.")
    args = parser.parse_args()

    missing = detect_missing_columns()
    if not missing:
        print("No missing SQLAlchemy model columns detected.")
        return 0

    print("Missing columns detected:")
    for item in missing:
        print(item.alter_sql)

    if args.apply:
        apply_missing_columns(missing)
        print("Missing columns applied.")
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
