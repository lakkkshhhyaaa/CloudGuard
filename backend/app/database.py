import os

from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL
from sqlalchemy.orm import declarative_base, sessionmaker


# Build the database URL from environment variables.
# URL.create safely handles special characters in passwords.
DATABASE_URL = URL.create(
    drivername="postgresql+psycopg",
    username=os.getenv("DB_USER"),
    password=os.getenv("DB_PASSWORD"),
    host=os.getenv("DB_HOST", "postgres"),
    port=int(os.getenv("DB_PORT", "5432")),
    database=os.getenv("DB_NAME", "cloudguard_app"),
)

# Create the SQLAlchemy database engine.
engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
)

# Create database sessions.
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)

# Base class for our database models.
Base = declarative_base()


# Dependency for database access in API routes.
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def test_db_connection():
    with engine.connect() as connection:
        connection.execute(text("SELECT 1"))
        return True