from core.db import redact_url


def test_the_database_password_is_masked():
    """Regression: scripts/init_db.py echoed the raw DATABASE_URL, password included, into
    terminals and logs. It runs in deployments, where that password is real."""
    rendered = redact_url("postgresql+psycopg2://cerberus:hunter2@db.internal:5432/cerberus")

    assert "hunter2" not in rendered
    assert "cerberus:***@db.internal:5432/cerberus" in rendered


def test_urls_without_a_password_are_left_readable():
    assert redact_url("sqlite:////tmp/cerberus.db") == "sqlite:////tmp/cerberus.db"


def test_special_characters_in_a_password_do_not_defeat_masking():
    rendered = redact_url("postgresql://user:p%40ss%2Fw0rd@host/db")
    assert "p%40ss" not in rendered and "w0rd" not in rendered
