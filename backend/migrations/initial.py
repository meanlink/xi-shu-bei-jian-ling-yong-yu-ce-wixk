from sqlalchemy import text, inspect
from src.config.database import Base, engine
from src import models


def _add_missing_columns():
    """对既有数据库做向前兼容的增量列迁移（create_all 不会修改旧表）。"""
    inspector = inspect(engine)
    if 'deliveries' not in inspector.get_table_names():
        return
    existing = {column['name'] for column in inspector.get_columns('deliveries')}
    statements = {
        'key_version': 'ALTER TABLE deliveries ADD COLUMN key_version INTEGER',
        'encryption_state': "ALTER TABLE deliveries ADD COLUMN encryption_state VARCHAR(20) NOT NULL DEFAULT 'pending'",
        'migrated_at': 'ALTER TABLE deliveries ADD COLUMN migrated_at DOUBLE PRECISION',
        'error': "ALTER TABLE deliveries ADD COLUMN error VARCHAR(1000) NOT NULL DEFAULT ''",
    }
    with engine.begin() as connection:
        for name, statement in statements.items():
            if name in existing:
                continue
            if engine.dialect.name == 'sqlite':
                statement = statement.replace('DOUBLE PRECISION', 'FLOAT')
            connection.execute(text(statement))
        if 'encryption_state' not in existing:
            # 既有归档在加密功能上线前是明文，全部纳入迁移队列。
            connection.execute(text(
                "UPDATE deliveries SET key_version = NULL, encryption_state = 'pending' WHERE filename <> ''"))


def migrate():
    Base.metadata.create_all(engine)
    _add_missing_columns()


if __name__ == '__main__':
    migrate()
