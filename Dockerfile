# Start by building the application.
# https://hub.docker.com/_/golang
# https://www.docker.com/blog/faster-multi-platform-builds-dockerfile-cross-compilation-guide/
FROM --platform=$BUILDPLATFORM golang:1.22.6 AS build

WORKDIR /app

# No shared libs in distroless
ENV CGO_ENABLED=0

ARG TARGETOS
ARG TARGETARCH
ENV GOOS=$TARGETOS
ENV GOARCH=$TARGETARCH

COPY ./go.* ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .

RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go build -o ./ntfa -ldflags "-s -w" .


##################################
# Now copy it into our base image.
FROM gcr.io/distroless/static-debian11:nonroot

COPY --from=build /app/ntfa /app/ntfa

ENTRYPOINT ["/app/ntfa"]

LABEL org.opencontainers.image.title=new-traefik-forward-auth
LABEL org.opencontainers.image.description="New Forward authentication service for the Traefik reverse proxy"
LABEL org.opencontainers.image.licenses=MIT
LABEL org.opencontainers.image.source=https://github.com/dsbferris/new-traefik-forward-auth
