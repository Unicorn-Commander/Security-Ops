"""ORM model registration and mapper configuration checks."""

from __future__ import annotations

from sqlalchemy.orm import configure_mappers


def test_all_model_mappers_configure():
    """Every model imported by app.models can be configured together."""
    import app.models as models

    configure_mappers()

    assert models.Finding.remediation.property.uselist is False
