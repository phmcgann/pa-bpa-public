import os
from typing import Iterator

from sqlalchemy import inspect, text
from sqlmodel import Session, SQLModel, create_engine

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app.db")
DATABASE_URL = os.environ.get("DATABASE_URL", f"sqlite:///{DB_PATH}")

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args)


def create_db_and_tables() -> None:
    SQLModel.metadata.create_all(engine)
    add_missing_columns()
    migrate_severity_scale()
    backfill_serials()


# Columns added to existing tables after release; create_all only creates missing tables.
_ADDED_COLUMNS = [
    ("assessment", "client_name", "VARCHAR"),
    ("assessment", "serial", "VARCHAR"),
    ("assessmentnote", "carried_from_id", "INTEGER"),
    ("assessment", "reanalyzed_at", "TIMESTAMP"),
    ("assessmentconfig", "cli_text_gz", "BLOB"),
]


def add_missing_columns() -> None:
    with engine.begin() as conn:
        insp = inspect(conn)
        for table, column, sql_type in _ADDED_COLUMNS:
            if column not in {c["name"] for c in insp.get_columns(table)}:
                if sql_type == "BLOB" and conn.dialect.name == "postgresql":
                    sql_type = "BYTEA"
                conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {sql_type}"))
                if column == "client_name":
                    conn.execute(text(f"CREATE INDEX IF NOT EXISTS ix_{table}_{column} ON {table} ({column})"))


# Severity scale v2: CRITICAL / HIGH / MEDIUM / LOW became CRITICAL / WARNING / LOW / INFORMATIONAL
# (each level renamed in place: HIGH -> WARNING, MEDIUM -> LOW, LOW -> INFORMATIONAL).
_SCORING_COLUMN_RENAMES = [  # order matters: free a name before reusing it
    ("weight_low", "weight_informational"),
    ("weight_medium", "weight_low"),
    ("weight_high", "weight_warning"),
    ("low_max", "informational_max"),
    ("medium_max", "low_max"),
    ("high_max", "warning_max"),
]


def migrate_severity_scale() -> None:
    from .models import AppMeta

    with engine.begin() as conn:
        columns = {c["name"] for c in inspect(conn).get_columns("scoringsettings")}
        if "weight_high" in columns:
            for old, new in _SCORING_COLUMN_RENAMES:
                conn.execute(text(f"ALTER TABLE scoringsettings RENAME COLUMN {old} TO {new}"))

    with Session(engine) as session:
        meta = session.get(AppMeta, 1) or AppMeta(id=1)
        if meta.severity_scale < 2:
            # One pass with CASE so a renamed LOW isn't renamed again.
            session.exec(text(
                "UPDATE rulesetting SET severity_override = CASE severity_override "
                "WHEN 'HIGH' THEN 'WARNING' WHEN 'MEDIUM' THEN 'LOW' WHEN 'LOW' THEN 'INFORMATIONAL' "
                "ELSE severity_override END"
            ))
            meta.severity_scale = 2
            session.add(meta)
            session.commit()


def backfill_serials() -> None:
    """Assessments saved before the serial column carry their serial only in parsed_data.
    Copy it into the column so serial lookups (client inheritance, grouping) find them."""
    from sqlmodel import select

    from .models import Assessment

    with Session(engine) as session:
        changed = False
        for a in session.exec(select(Assessment).where(Assessment.serial.is_(None))):
            serial = ((a.parsed_data or {}).get("system_info") or {}).get("serial")
            if serial and serial != "N/A":
                a.serial = serial
                session.add(a)
                changed = True
        if changed:
            session.commit()


def get_session() -> Iterator[Session]:
    with Session(engine) as session:
        yield session
