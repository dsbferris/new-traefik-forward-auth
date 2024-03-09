
format:
	gofmt -w -s .

test:
	go test -v ./...


buildx:
	docker buildx create --name bob --use

build: 
	docker buildx build --load -t ghcr.io/dsbferris/traefik-forward-auth:latest . 

push:
	docker buildx build --platform=linux/amd64,linux/arm64 --push -t ghcr.io/dsbferris/traefik-forward-auth:latest . 

.PHONY: format test
