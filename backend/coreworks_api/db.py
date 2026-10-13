from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase

from coreworks_api.config import settings


class Base(DeclarativeBase):
    pass


engine = create_engine(settings.database_url, pool_pre_ping=True)
