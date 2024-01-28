# Copyright 2024 Leon Hwang.
# SPDX-License-Identifier: Apache-2.0

TARGET_GOARCH := amd64

GOGEN := go generate
GOBUILD := CGO_ENABLED=0 go build -ldflags="-s -w"

BPF_SRC := ./bpf/sock_trace.c
BPF_OBJ := kprobemultisocktrace_bpfel_x86.o kprobesocktrace_bpfel_x86.o

GO_SRC := $(shell find . -name "*.go" -type f) $(shell find ./internal/socketrace -name "*.go" -type f)
GO_OBJ := socketrace

$(BPF_OBJ): $(BPF_SRC)
	TARGET_GOARCH=$(TARGET_GOARCH) $(GOGEN) .

$(GO_OBJ): $(GO_SRC)
	GOOS=linux $(GOBUILD) -o $@ .

.DEFAULT_GOAL := build
.PHONY: build
build: $(BPF_OBJ) $(GO_OBJ)

.PHONY: clean
clean:
	rm -vf $(BPF_OBJ) $(GO_OBJ)

