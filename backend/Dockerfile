FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app/backend

COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ .
COPY alembic.ini /app/alembic.ini
COPY alembic/ /app/alembic/
COPY model/ /app/model/
COPY frontend/ /app/frontend/

EXPOSE 8000

CMD ["sh", "-c", "alembic -c /app/alembic.ini upgrade head && uvicorn main:app --host 0.0.0.0 --port 8000"]
