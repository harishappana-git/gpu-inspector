GO ?= go
CMAKE ?= cmake
CTEST ?= ctest
JOBS ?= 2
CUDA_ROOT ?= /usr/local/cuda

.DEFAULT_GOAL := build
.PHONY: build build-linux test test-race vet worker-cpu worker-cuda release-check

build:
	mkdir -p bin
	$(GO) build -trimpath -o bin/gri ./cmd/gri

build-linux:
	mkdir -p bin
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -o bin/gri-linux-amd64 ./cmd/gri

test:
	$(GO) test ./...

test-race:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

worker-cpu:
	$(CMAKE) -S worker -B build/worker-cpu -DGRI_BUILD_CUDA=OFF -DCMAKE_BUILD_TYPE=Debug
	$(CMAKE) --build build/worker-cpu --parallel $(JOBS)
	$(CTEST) --test-dir build/worker-cpu --output-on-failure

worker-cuda:
	$(CMAKE) -S worker -B build/worker-cuda -DGRI_BUILD_CUDA=ON -DCMAKE_BUILD_TYPE=Release -DCUDAToolkit_ROOT="$(CUDA_ROOT)"
	$(CMAKE) --build build/worker-cuda --parallel $(JOBS)
	$(CTEST) --test-dir build/worker-cuda --output-on-failure

release-check: test test-race vet build build-linux worker-cpu
	@printf '%s\n' 'Local development checks completed. Production release gates remain in docs/ACCEPTANCE.md; no signing, publication or deployment occurred.'
