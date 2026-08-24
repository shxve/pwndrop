# syntax=docker/dockerfile:1

# ---- build stage ----
# go.mod requires Go >= 1.25; deps are vendored so the build needs no network.
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -mod=vendor -ldflags="-s -w" -o /out/pwndrop main.go

# ---- runtime stage ----
FROM alpine:3.20
RUN apk add --no-cache ca-certificates && adduser -D -H pwndrop
WORKDIR /app
# binary + admin panel (pwndrop serves ./admin relative to the config's admin_dir)
COPY --from=build /out/pwndrop /app/pwndrop
COPY --from=build /src/www      /app/admin
COPY docker/pwndrop.ini.default /app/pwndrop.ini.default
COPY docker/entrypoint.sh       /app/entrypoint.sh
RUN chmod +x /app/pwndrop /app/entrypoint.sh

# Persisted state (DB, TLS certs, live config) lives here; mount a volume.
VOLUME ["/data"]
# Local defaults: HTTP 8080, HTTPS 8443. Map to 80/443 in production.
EXPOSE 8080 8443 53/udp

ENTRYPOINT ["/app/entrypoint.sh"]
# Overridden by docker-compose for local dev (adds -no-autocert -no-dns).
CMD ["-config", "/data/pwndrop.ini"]
