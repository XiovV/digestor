BIN := digestor

.PHONY: build run dry-run vet test

build:
	go build -o $(BIN) ./cmd/digestor

run:
	go run ./cmd/digestor

dry-run:
	go run ./cmd/digestor -dry-run -v

vet:
	go vet ./...

test:
	go test ./...
