# Start by building the application.
# https://hub.docker.com/_/golang
# https://www.docker.com/blog/faster-multi-platform-builds-dockerfile-cross-compilation-guide/
FROM --platform=$BUILDPLATFORM golang:1.22.1

WORKDIR /app

# No shared libs in distroless
ENV CGO_ENABLED 0

COPY ./go.* ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .
ARG TARGETOS
ARG TARGETARCH
ENV GOOS=$TARGETOS
ENV GOARCH=$TARGETARCH
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go build -o ./traefik-forward-auth -ldflags "-s -w" ./cmd


##################################
# Now copy it into our base image.
#FROM gcr.io/distroless/static-debian11:nonroot

#COPY --from=build /app/traefik-forward-auth /app/traefik-forward-auth

ENTRYPOINT ["/app/traefik-forward-auth"]
#CMD []

LABEL org.opencontainers.image.title=traefik-forward-auth
LABEL org.opencontainers.image.description="Forward authentication service for the Traefik reverse proxy"
LABEL org.opencontainers.image.licenses=MIT
LABEL org.opencontainers.image.source=https://github.com/dsbferris/traefik-forward-auth
