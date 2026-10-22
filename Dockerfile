# Multi-stage build: compile the React frontend, then serve everything from the FastAPI app.
FROM node:20-bookworm-slim AS frontend
WORKDIR /app/frontend
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm install --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim-bookworm AS app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app/backend
COPY backend/requirements.txt backend/requirements-dev.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/ ./
# Built static assets served by FastAPI at "/"
COPY --from=frontend /app/frontend/dist /app/frontend/dist
# Train the advisory model at build time so the image is self-contained and offline.
RUN python -m scripts.train_model
EXPOSE 8000
# Shell form so ${PORT} expands: Render (and other PaaS) inject PORT; locally it defaults to 8000, so
# docker-compose and `docker run -p 8000:8000` keep working unchanged.
CMD python -m uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}
