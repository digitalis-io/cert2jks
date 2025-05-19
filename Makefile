BINARY_NAME=cert2jks
CGO_ENABLED=1

build:
	@mkdir -p dist
ifeq ($(shell uname), Linux)
	@go build -ldflags="-linkmode external -v -extldflags '-static'" -o dist/$(BINARY_NAME) main.go
else
	@go build -o dist/$(BINARY_NAME) main.go
endif

clean:
	@rm -f dist/$(BINARY_NAME)

.PHONY: build clean
.EXPORT_ALL_VARIABLES:
