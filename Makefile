
format:
	gofmt -w -s tfa/

test:
	go test -v ./tfa/...


buildx:
	docker buildx create --name bob --use

build-dev: 
	docker buildx build \
		--load \
		-t ghcr.io/dsbferris/traefik-forward-auth:dev \
		-f dev.Dockerfile \
		. 

build:
	docker buildx build \
		--load \
		-t ghcr.io/dsbferris/traefik-forward-auth:latest \
		-f Dockerfile \
		. 

push:
	docker buildx build --platform=linux/amd64,linux/arm64 --push -t ghcr.io/dsbferris/traefik-forward-auth:latest . 

.PHONY: format test
