.PHONY: all clean deps fmt vet test docker

VERSION ?= $(shell git describe --match 'v[0-9]*' --dirty='-dev' --always)
COMMIT ?= $(shell git rev-parse --short HEAD)

LDFLAGS = -X "hypercheck.Revision=$(COMMIT)" -X "hypercheck.Version=$(VERSION)"
PACKAGES = $(shell go list ./... | grep -v /vendor/)
FILES = $(shell find . -type f -print | grep -v vendor | grep "\.go")

release:
	@echo "Release v$(version)"
	@git pull
	@git checkout master
	@git pull
	@git checkout develop
	@git flow release start $(version)
	@echo "$(version)" > .version
	@sed -e "s/version: .*/version: \"v$(version)\"/g" docs/swagger.yaml > docs/swagger.yaml.new && rm -rf docs/swagger.yaml && mv docs/swagger.yaml.new docs/swagger.yaml
	@git add .version docs/swagger.yaml
	@git commit -m "feat(project): update version file" .version docs/swagger.yaml
	@git flow release finish $(version)
	@git push
	@git push --tags
	@git checkout master
	@git push
	@git checkout develop
	@echo "Release v$(version) finished."

all: deps build test

clean:
	@go clean -i ./...

deps:
	@dep ensure

test:
	@go test -ldflags '-s -w $(LDFLAGS)' ./...

cover:
	@go test -ldflags '-s -w $(LDFLAGS)' -cover -covermode=set -coverprofile=coverage.out ./...
	@go tool cover -func ./coverage.out

build: build-hypercheck-api build-hypercheck-dns-agent build-hypercheck-http-agent build-hypercheck-ssl-agent build-hypercheck-scheduler

build-hypercheck-api: $(FILES)
	@echo "Building hypercheck-api..."
	@go generate ./cmd/hypercheck-api/
	@CGO_ENABLED=0 go build ./cmd/hypercheck-api/

run-hypercheck-api: build-hypercheck-api
	@./hypercheck-api

build-hypercheck-dns-agent: $(FILES)
	@echo "Building hypercheck-dns-agent..."
	@go generate ./cmd/hypercheck-dns-agent/
	@CGO_ENABLED=0 go build ./cmd/hypercheck-dns-agent/

run-hypercheck-dns-agent: build-hypercheck-dns-agent
	@./hypercheck-dns-agent

build-hypercheck-http-agent: $(FILES)
	@echo "Building hypercheck-http-agent..."
	@go generate ./cmd/hypercheck-http-agent/
	@CGO_ENABLED=0 go build ./cmd/hypercheck-http-agent/

run-hypercheck-http-agent: build-hypercheck-http-agent
	@./hypercheck-http-agent

build-hypercheck-ssl-agent: $(FILES)
	@echo "Building hypercheck-ssl-agent..."
	@go generate ./cmd/hypercheck-ssl-agent/
	@CGO_ENABLED=0 go build ./cmd/hypercheck-ssl-agent/

run-hypercheck-ssl-agent: build-hypercheck-ssl-agent
	@./hypercheck-ssl-agent

build-hypercheck-scheduler: $(FILES)
	@echo "Building hypercheck-scheduler..."
	@go generate ./cmd/hypercheck-scheduler/
	@CGO_ENABLED=0 go build ./cmd/hypercheck-scheduler/

run-hypercheck-scheduler: build-hypercheck-scheduler
	@./hypercheck-scheduler

stack-deploy:
	@docker stack deploy -c docker-compose.yml hypercheck
