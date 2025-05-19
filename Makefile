BINARY_NAME=cert2jks
CGO_ENABLED=1

build:
	@mkdir -p dist
	@go build -o dist/$(BINARY_NAME) main.go

clean:
	@rm -f dist/$(BINARY_NAME)

.PHONY: build clean
.EXPORT_ALL_VARIABLES:
