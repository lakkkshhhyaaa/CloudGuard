
FROM python:3.13-slim

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

# Application code
COPY app/ ./app/

# Automated tests
COPY tests/ ./tests/

# Alembic configuration and migration scripts
COPY alembic.ini ./alembic.ini
COPY migrations/ ./migrations/

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
