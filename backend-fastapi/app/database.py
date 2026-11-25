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
    from sqlalchemy import inspect, text
    inspector=inspect(engine)
    if 'flow_logs' in inspector.get_table_names():
        columns={c['name'] for c in inspector.get_columns('flow_logs')}
        with engine.begin() as conn:
            if 'input_representation' not in columns:
                conn.execute(text("ALTER TABLE flow_logs ADD COLUMN input_representation VARCHAR(64) DEFAULT 'dataset_features'"))
            if 'artifact_sha256' not in columns:
                conn.execute(text("ALTER TABLE flow_logs ADD COLUMN artifact_sha256 VARCHAR(64) DEFAULT ''"))
            duplicates=conn.execute(text('SELECT window_id FROM flow_logs GROUP BY window_id HAVING COUNT(*)>1 LIMIT 1')).first()
            if duplicates: raise ValueError('Legacy database contains duplicate window IDs; archive it and select a fresh DATABASE_URL')
            conn.execute(text('CREATE UNIQUE INDEX IF NOT EXISTS uq_flow_window ON flow_logs(window_id)'))
    for table in ('flow_logs','incidents'):
        if table in inspector.get_table_names() and 'capture_session_id' not in {c['name'] for c in inspector.get_columns(table)}:
            with engine.begin() as conn:
                conn.execute(text(f"ALTER TABLE {table} ADD COLUMN capture_session_id VARCHAR(64) DEFAULT ''"))
    extra_columns = {
        'flow_logs': {'collector_id': 'VARCHAR(64)'},
        'incidents': {
            'collector_id': 'VARCHAR(64)', 'capture_mode': "VARCHAR(32) DEFAULT ''",
            'input_representation': "VARCHAR(64) DEFAULT 'dataset_features'",
        },
        'security_alerts': {
            'collector_id': 'VARCHAR(64)', 'capture_mode': "VARCHAR(32) DEFAULT ''",
            'input_representation': "VARCHAR(64) DEFAULT 'dataset_features'",
        },
    }
    with engine.begin() as conn:
        existing = inspect(conn)
        for table, definitions in extra_columns.items():
            if not existing.has_table(table):
                continue
            columns = {c['name'] for c in existing.get_columns(table)}
            for name, definition in definitions.items():
                if name not in columns:
                    conn.execute(text(f'ALTER TABLE {table} ADD COLUMN {name} {definition}'))
        if existing.has_table('flow_logs'):
            conn.execute(text('CREATE INDEX IF NOT EXISTS ix_flow_live_activity ON flow_logs(capture_mode, timestamp, collector_id)'))
    Base.metadata.create_all(engine)
    return engine, sessionmaker(engine, expire_on_commit=False)
