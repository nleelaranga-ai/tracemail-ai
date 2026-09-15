"""
TraceMail AI Backend — Database Connection & Session Management
Supports SQLAlchemy 2.0 with PostgreSQL/SQLite, plus zero-dependency fallback for tests.
"""
from typing import Generator, Any, Optional, List
from backend.utils.config import settings
from backend.utils.logger import logger

try:
    from sqlalchemy import create_engine, Column as SAColumn, String as SAString, Integer as SAInteger
    from sqlalchemy import Boolean as SABoolean, DateTime as SADateTime, Text as SAText, JSON as SAJSON
    from sqlalchemy.orm import declarative_base, sessionmaker, Session
    _HAS_SQLALCHEMY = True
except ImportError:
    _HAS_SQLALCHEMY = False


if _HAS_SQLALCHEMY:
    db_url = settings.DATABASE_URL
    if db_url.startswith("postgres://"):
        db_url = db_url.replace("postgres://", "postgresql://", 1)

    engine_kwargs = {"echo": False}
    if db_url.startswith("sqlite"):
        engine_kwargs["connect_args"] = {"check_same_thread": False}
    else:
        # Production connection pooling for PostgreSQL (Railway / Cloud)
        engine_kwargs["pool_pre_ping"] = True
        engine_kwargs["pool_recycle"] = 300
        engine_kwargs["pool_size"] = 10
        engine_kwargs["max_overflow"] = 20

    engine = create_engine(
        db_url,
        **engine_kwargs
    )
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base = declarative_base()

    Column = SAColumn
    String = SAString
    Integer = SAInteger
    Boolean = SABoolean
    DateTime = SADateTime
    Text = SAText
    JSON = SAJSON

    def get_db() -> Generator[Session, None, None]:
        db = SessionLocal()
        try:
            yield db
        finally:
            db.close()

    def _sync_table_columns():
        """Auto-migrates missing columns for existing tables to prevent schema drift."""
        try:
            from sqlalchemy import inspect, text
            inspector = inspect(engine)
            existing_tables = set(inspector.get_table_names())
            with engine.connect() as conn:
                # On PostgreSQL, widen indicator and IOC value columns to TEXT so long URLs never truncate
                if engine.dialect.name == "postgresql":
                    try:
                        conn.execute(text('ALTER TABLE "threat_results" ALTER COLUMN "indicator_value" TYPE TEXT'))
                        conn.commit()
                    except Exception:
                        pass
                    try:
                        conn.execute(text('ALTER TABLE "ioc_entities" ALTER COLUMN "ioc_value" TYPE TEXT'))
                        conn.commit()
                    except Exception:
                        pass

                for table_name, table in Base.metadata.tables.items():
                    if table_name not in existing_tables:
                        continue
                    db_columns = {col["name"] for col in inspector.get_columns(table_name)}
                    for col in table.columns:
                        if col.name not in db_columns:
                            col_type = col.type.compile(engine.dialect)
                            logger.info(f"Auto-migrating missing column {table_name}.{col.name} ({col_type})")
                            try:
                                conn.execute(text(f'ALTER TABLE "{table_name}" ADD COLUMN "{col.name}" {col_type}'))
                                conn.commit()
                            except Exception as alt_err:
                                logger.warning(f"Notice auto-adding column {table_name}.{col.name}: {alt_err}")
        except Exception as e:
            logger.warning(f"Auto-migration check notice: {e}")

    def init_db():
        try:
            # Eagerly import all models to ensure complete Base.metadata registration
            import backend.models  # noqa: F401
            Base.metadata.create_all(bind=engine)
            _sync_table_columns()
            logger.info("SQLAlchemy database tables verified and initialized in PostgreSQL/SQLite.")
        except Exception as e:
            logger.warning(f"Database init notice: {e}")

else:
    # High-performance zero-dependency database emulation for standalone test runner
    class ColumnExpr:
        def __init__(self, name: str):
            self.name = name

        def __eq__(self, other):
            return lambda obj: getattr(obj, self.name, None) == other

        def __ne__(self, other):
            return lambda obj: getattr(obj, self.name, None) != other

        def desc(self):
            return self

    class Column:
        def __init__(self, *args, **kwargs):
            self.primary_key = kwargs.get("primary_key", False)
            self.default = kwargs.get("default", None)
            self.nullable = kwargs.get("nullable", True)
            self.index = kwargs.get("index", False)
            self.name = None

        def __set_name__(self, owner, name):
            self.name = name

        def __get__(self, instance, owner):
            if instance is None:
                return ColumnExpr(self.name)
            return instance.__dict__.get(self.name, self.default() if callable(self.default) else self.default)

        def __set__(self, instance, value):
            instance.__dict__[self.name] = value

    class String:
        def __init__(self, *args, **kwargs): pass
    class Integer:
        def __init__(self, *args, **kwargs): pass
    class Boolean:
        def __init__(self, *args, **kwargs): pass
    class DateTime:
        def __init__(self, *args, **kwargs): pass
    class Text:
        def __init__(self, *args, **kwargs): pass
    class JSON:
        def __init__(self, *args, **kwargs): pass

    class MockBase:
        def __init__(self, **kwargs):
            # Apply defaults
            for name, attr in type(self).__dict__.items():
                if isinstance(attr, Column):
                    if attr.default is not None:
                        val = attr.default() if callable(attr.default) else attr.default
                        setattr(self, name, val)
            for k, v in kwargs.items():
                setattr(self, k, v)

    Base = MockBase
    _GLOBAL_STORE = {}

    class MockQuery:
        def __init__(self, records: List[Any], model_cls: Any):
            self._records = list(records)
            self._model_cls = model_cls

        def filter(self, *criteria):
            res = self._records
            for crit in criteria:
                if callable(crit):
                    res = [r for r in res if crit(r)]
            return MockQuery(res, self._model_cls)

        def order_by(self, *args):
            return self

        def limit(self, count: int):
            return MockQuery(self._records[:count], self._model_cls)

        def first(self):
            return self._records[0] if self._records else None

        def all(self):
            return list(self._records)

        def count(self):
            return len(self._records)

    class MockSession:
        def query(self, model_cls):
            tbl = getattr(model_cls, "__tablename__", model_cls.__name__)
            if tbl not in _GLOBAL_STORE:
                _GLOBAL_STORE[tbl] = []
            return MockQuery(_GLOBAL_STORE[tbl], model_cls)

        def add(self, obj):
            tbl = getattr(type(obj), "__tablename__", type(obj).__name__)
            if tbl not in _GLOBAL_STORE:
                _GLOBAL_STORE[tbl] = []
            if obj not in _GLOBAL_STORE[tbl]:
                _GLOBAL_STORE[tbl].append(obj)

        def commit(self):
            pass

        def refresh(self, obj):
            pass

        def close(self):
            pass

    engine = None
    SessionLocal = MockSession
    Session = MockSession

    def get_db():
        db = MockSession()
        try:
            yield db
        finally:
            db.close()

    def init_db():
        logger.info("Memory database initialized.")
