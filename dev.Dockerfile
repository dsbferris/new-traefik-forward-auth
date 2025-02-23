# Start by building the application.
# https://hub.docker.com/_/golang
# https://www.docker.com/blog/faster-multi-platform-builds-dockerfile-cross-compilation-guide/
FROM --platform=$BUILDPLATFORM golang:1.24.0

WORKDIR /app

ARG TARGETOS
ARG TARGETARCH
ENV GOOS=$TARGETOS
ENV GOARCH=$TARGETARCH

# Running the go mod download here with only go.mod and go.sum
# allows for efficient docker image layer caching
COPY ./go.* ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go build -o ./ntfa .


ENTRYPOINT ["/app/ntfa"]
# ENTRYPOINT [ "/usr/bin/bash" ]

LABEL org.opencontainers.image.title=new-traefik-forward-auth
LABEL org.opencontainers.image.description="New Forward authentication service for the Traefik reverse proxy"
LABEL org.opencontainers.image.licenses=MIT
LABEL org.opencontainers.image.source=https://github.com/dsbferris/new-traefik-forward-auth
