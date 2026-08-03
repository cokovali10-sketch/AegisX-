.PHONY: proto recon shadowpot fim phishguard cc all clean

SHELL := /bin/bash
PROTOC      ?= protoc
GO           = go
CARGO        = cargo
PYTHON       = python3

PROTO_DIR   := proto
GEN_DIR     := $(PROTO_DIR)/gen
GO_PB_DIR   := $(GEN_DIR)/go
PY_PB_DIR   := $(GEN_DIR)/python

# ---------------------------------------------------------------------------
# Code generation from the single IDL
# ---------------------------------------------------------------------------
proto: proto-go proto-py proto-kotlin

proto-go:
	mkdir -p $(GO_PB_DIR)
	$(PROTOC) --proto_path=$(PROTO_DIR) \
	  --go_out=$(GEN_DIR)/go --go_opt=paths=source_relative \
	  --go-grpc_out=$(GEN_DIR)/go --go-grpc_opt=paths=source_relative \
	  $(PROTO_DIR)/aegisx.proto

proto-py:
	mkdir -p $(PY_PB_DIR)
	$(PYTHON) -m grpc_tools.protoc --proto_path=$(PROTO_DIR) \
	  --python_out=$(PY_PB_DIR) --grpc_python_out=$(PY_PB_DIR) \
	  $(PROTO_DIR)/aegisx.proto

proto-kotlin:
	mkdir -p $(GEN_DIR)/kotlin
	$(PROTOC) --proto_path=$(PROTO_DIR) --kotlin_out=$(GEN_DIR)/kotlin \
	  --plugin=protoc-gen-kotlin=$(shell which protoc-gen-kotlin) \
	  $(PROTO_DIR)/aegisx.proto

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
recon:
	cd sentinel-recon && $(GO) build -o bin/aegisx-recon ./cmd/aegisx-recon

shadowpot:
	cd shadowpot && $(GO) build -o bin/aegisx-shadowpot ./cmd/aegisx-shadowpot

fim:
	cd zerotrust-fim && $(CARGO) build --release --features ffi

phishguard:
	cd phishguard && $(PYTHON) -m pip install -r requirements.txt

cc:
	cd control-center && ./gradlew build

# ---------------------------------------------------------------------------
all: proto recon shadowpot fim phishguard

clean:
	rm -rf $(GEN_DIR) sentinel-recon/bin shadowpot/bin \
	       zerotrust-fim/target control-center/build
