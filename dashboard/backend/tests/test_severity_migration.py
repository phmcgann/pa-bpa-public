"""Databases created before the Critical / Warning / Low / Informational scale are migrated."""
import importlib

from sqlalchemy import create_engine, text


def test_old_database_is_migrated(tmp_path, monkeypatch):
    url = f"sqlite:///{tmp_path / 'old.db'}"
    old = create_engine(url)
    with old.begin() as conn:
        conn.execute(text(
            "CREATE TABLE scoringsettings (id INTEGER PRIMARY KEY, weight_critical INTEGER, weight_high INTEGER, "
            "weight_medium INTEGER, weight_low INTEGER, low_max INTEGER, medium_max INTEGER, high_max INTEGER)"
        ))
        conn.execute(text("INSERT INTO scoringsettings VALUES (1, 10, 6, 3, 1, 2, 20, 50)"))
        conn.execute(text(
            "CREATE TABLE rulesetting (rule_id VARCHAR PRIMARY KEY, enabled BOOLEAN, threshold_overrides JSON, "
            "severity_override VARCHAR)"
        ))
        conn.execute(text(
            "INSERT INTO rulesetting VALUES ('a', 1, NULL, 'HIGH'), ('b', 1, NULL, 'MEDIUM'), "
            "('c', 1, NULL, 'LOW'), ('d', 1, NULL, 'CRITICAL'), ('e', 1, NULL, NULL)"
        ))
    old.dispose()

    monkeypatch.setenv("DATABASE_URL", url)
    from app import db
    importlib.reload(db)
    db.create_db_and_tables()
    db.create_db_and_tables()  # idempotent: a second start must not remap again

    with db.engine.connect() as conn:
        row = conn.execute(text(
            "SELECT weight_critical, weight_warning, weight_low, weight_informational, "
            "informational_max, low_max, warning_max FROM scoringsettings"
        )).one()
        assert tuple(row) == (10, 6, 3, 1, 2, 20, 50)
        overrides = dict(conn.execute(text("SELECT rule_id, severity_override FROM rulesetting")).all())
    assert overrides == {"a": "WARNING", "b": "LOW", "c": "INFORMATIONAL", "d": "CRITICAL", "e": None}


def test_fresh_database_gets_new_columns(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'new.db'}")
    from app import db
    importlib.reload(db)
    db.create_db_and_tables()
    with db.engine.connect() as conn:
        cols = [r[1] for r in conn.execute(text("PRAGMA table_info(scoringsettings)")).all()]
    assert {"weight_warning", "weight_informational", "informational_max", "warning_max"} <= set(cols)
