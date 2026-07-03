"""SQLAlchemy declarative Base for model definitions.

Engine, session, and lifecycle live in app.database — this module exists
solely to break the circular import that would occur if models imported
Base from the same module that imports models during init_db().
"""

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass
