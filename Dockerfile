# syntax=docker/dockerfile:1.6
# ManyRows Docker build.
#
# Three-stage:
#   1. ui-build  — node, builds appkit-ui + manyrows-ui, drops the
#                  bundles into the locations the Go binary embeds.
#   2. go-build  — golang, compiles the static binary with embedded UI.
#   3. runtime   — minimal alpine, just the binary + ca-certs + tzdata.
#
# Builds the two workspaces the server image embeds: appkit-ui (the
# AppKit-bundled auth UI) and manyrows-ui (the admin app). appkit-react
# is the npm-published SDK for customers and is NOT built here —
# manyrows-ui only shows its import line as a copy-paste code sample,
# it doesn't import the package.
#
# Build:    docker build -t manyrows .
# Run:      docker run -p 8080:8080 -e DATABASE_URL=... manyrows
# Compose:  docker compose up    (handles Postgres + env wiring for you)

# -----------------------------------------------------------------------
# Stage 1 — UI bundles
# -----------------------------------------------------------------------
FROM node:22-alpine AS ui-build
WORKDIR /work

# Copy just enough to install workspace deps in cache-friendly order.
COPY package.json package-lock.json* ./
COPY appkit-ui/package.json    appkit-ui/
COPY manyrows-ui/package.json  manyrows-ui/

# `npm install` walks workspaces declared in the root package.json.
# `--workspaces` here is implicit; explicit for clarity.
RUN npm install --workspaces --include-workspace-root --no-audit --no-fund

# Now bring the source. Splitting from the install layer keeps
# dependency-only edits from invalidating the source-copy layer.
COPY appkit-ui    appkit-ui
COPY manyrows-ui  manyrows-ui

# Both workspaces are independent:
#   - appkit-ui   → embedded into manyrows-core/appkit
#   - manyrows-ui → embedded into manyrows-core/web
RUN npm run build --workspace=appkit-ui \
 && npm run build --workspace=manyrows-ui

# -----------------------------------------------------------------------
# Stage 2 — Go binary with embedded assets
# -----------------------------------------------------------------------
FROM golang:1.26-alpine AS go-build
WORKDIR /work

# Module download layer first, so source edits don't re-pull deps.
COPY manyrows-core/go.mod manyrows-core/go.sum manyrows-core/
WORKDIR /work/manyrows-core
RUN go mod download

# Source.
WORKDIR /work
COPY manyrows-core manyrows-core

# Drop the built UI bundles into the locations the embed directives
# expect (manyrows-core/web for the admin app, manyrows-core/appkit
# for the AppKit-bundled auth UI). Mirrors build-ui.sh.
RUN rm -rf manyrows-core/web/assets manyrows-core/appkit/appkit/assets
COPY --from=ui-build /work/appkit-ui/dist/.   manyrows-core/appkit/
COPY --from=ui-build /work/manyrows-ui/dist/. manyrows-core/web/

# Static binary. CGO disabled so the runtime image needs nothing
# beyond glibc-free musl.
#
# VERSION arg lets the CI / docker build command pass through
# `git describe --tags --always --dirty` (set externally because the
# `.git/` directory isn't shipped into the image). Falls back to "dev"
# when unset so plain `docker build .` still works.
WORKDIR /work/manyrows-core
ARG VERSION=dev
ENV CGO_ENABLED=0 GOOS=linux
RUN go build -trimpath -ldflags="-s -w -X main.Version=${VERSION}" -o /out/manyrows ./start.go

# -----------------------------------------------------------------------
# Stage 3 — Runtime
# -----------------------------------------------------------------------
FROM alpine:3.20 AS runtime
RUN apk add --no-cache ca-certificates tzdata \
 && addgroup -S manyrows && adduser -S -G manyrows manyrows
USER manyrows
WORKDIR /app
COPY --from=go-build /out/manyrows /app/manyrows

# Heroku/PaaS-friendly: respect $PORT when set; fall back to 8080.
EXPOSE 8080
ENV MANYROWS_PROFILE=prod
ENTRYPOINT ["/app/manyrows"]
