FROM golang:1.23-bookworm AS service
RUN apt-get update && apt-get install -y --no-install-recommends libpcap-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY collector-go/ ./
RUN CGO_ENABLED=1 go build -trimpath -o /out/sentinel-service-linux-$(go env GOARCH) . && cd /out && sha256sum sentinel-service-* > LIVE-SHA256SUMS
FROM node:22-bookworm-slim AS ui
WORKDIR /ui
COPY frontend-react/package*.json ./
RUN npm ci
COPY frontend-react/ ./
RUN npm run build
FROM python:3.11-slim-bookworm AS api
WORKDIR /repo
COPY pyproject.toml ./
COPY sentinel_ml/ sentinel_ml/
COPY backend-fastapi/ backend-fastapi/
RUN pip install --no-cache-dir -e . -r backend-fastapi/requirements.txt
COPY ml/artifacts/ ml/artifacts/
COPY scripts/ scripts/
COPY --from=service /out/ dist/collectors/
WORKDIR /repo/backend-fastapi
CMD ["uvicorn","app.main:app","--host","0.0.0.0","--port","8000"]
FROM caddy:2 AS web
COPY --from=ui /ui/dist /srv
COPY deploy/Caddyfile /etc/caddy/Caddyfile
