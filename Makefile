APP_NAME ?= wisp
APP_DIR  ?= ./cmd/$(APP_NAME)
BIN_DIR  ?= ./bin
BIN      ?= $(BIN_DIR)/$(APP_NAME)

# --- Runtime config (override per-env or in CI) ---
PORT ?= 8081
JWT_SECRET ?= dev-secret-please-change
DB_HOST ?= postgres-postgresql.postgres.svc.cluster.local
DB_PORT ?= 5432
DB_USER ?= wisp
DB_PASSWORD ?= wisp123
DB_NAME ?= wispdb
REDIS_ADDR ?= 127.0.0.1:6379
REDIS_PASSWORD ?=

export PORT JWT_SECRET DB_HOST DB_PORT DB_USER DB_PASSWORD DB_NAME REDIS_ADDR REDIS_PASSWORD

.PHONY: run build clean test routes docker docker-push dockerx dockerx-push release

run:
	@echo "→ running $(APP_NAME) on :$(PORT)"
	go run $(APP_DIR)

build:
	@mkdir -p $(BIN_DIR)
	go build -o $(BIN) $(APP_DIR)
	@echo "→ built $(BIN)"

clean:
	rm -rf $(BIN_DIR)

test:
	go test ./...

# Handy: print the routes once server is up (relies on your /__routes)
routes:
	@echo "→ GET http://127.0.0.1:$(PORT)/__routes (start server first)"
	@curl -s --fail http://127.0.0.1:$(PORT)/__routes | jq .

# ---- Docker config ----
REGISTRY ?= ghcr.io
GH_USER ?= sraza0098
IMAGE ?= $(REGISTRY)/$(GH_USER)/wisp-backend
TAG ?= dev
PLATFORMS ?= linux/amd64,linux/arm64/v8

# Pass version into the image; your app reads WISP_VERSION from ENV
DOCKER_BUILD_ARGS = --build-arg WISP_VERSION=$(TAG)

docker:
	# Single-arch local build
	docker build \
	  $(DOCKER_BUILD_ARGS) \
	  -t $(IMAGE):$(TAG) \
	  -f Dockerfile .

docker-push: docker
	docker push $(IMAGE):$(TAG)

dockerx:
	# Multi-arch build & push with buildx (creates builder if needed)
	- docker buildx create --use >/dev/null 2>&1 || true
	docker buildx build \
	  --platform $(PLATFORMS) \
	  $(DOCKER_BUILD_ARGS) \
	  -t $(IMAGE):$(TAG) \
	  -t $(IMAGE):dev \
	  -f Dockerfile \
	  --push .

# Convenience for your exact flow:
# make release TAG=0.1.4
release:
	$(MAKE) dockerx TAG=$(TAG)
