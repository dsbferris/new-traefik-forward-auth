

VERSION=$(shell cat VERSION)

format:
	gofmt -w -s tfa/

test:
	go test -v ./tfa/...


buildx:
	docker buildx create --name bob --use

build-dev: 
	docker buildx build \
		--load \
		-f dev.Dockerfile \
		-t ghcr.io/dsbferris/traefik-forward-auth:dev \
		. 

build:
	docker buildx build \
		--load \
		-f Dockerfile \
		-t ghcr.io/dsbferris/traefik-forward-auth:latest \
		-t ghcr.io/dsbferris/traefik-forward-auth:$(VERSION) \
		. 

push:
	docker buildx build \
		--platform linux/amd64,linux/arm64 \
		--push \
		-f Dockerfile \
		-t ghcr.io/dsbferris/traefik-forward-auth:latest \
		-t ghcr.io/dsbferris/traefik-forward-auth:$(VERSION) \
		. 
	git tag $(VERSION)
	git push origin $(VERSION)

delete-push:
	git tag -d $(VERSION)
	git push -d origin $(VERSION)
	echo "Delete the package at github"

.PHONY: format test
