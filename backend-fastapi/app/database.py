"""SQLite persistence shared by ingestion and dashboard queries."""
import os
from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, sessionmaker

class Base(DeclarativeBase):
    pass

def initialize():
    engine = create_engine(os.getenv('DATABASE_URL', 'sqlite:///./sentinel_soc.db'), connect_args={'check_same_thread': False})
    @event.listens_for(engine, 'connect')
    def configure(connection, _):
        connection.execute('PRAGMA journal_mode=WAL')
        connection.execute('PRAGMA foreign_keys=ON')
        connection.execute('PRAGMA busy_timeout=5000')
    Base.metadata.create_all(engine)
    return engine, sessionmaker(engine, expire_on_commit=False)
