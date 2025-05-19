BINARY_NAME=cert2jks
CGO_ENABLED=1
STATIC ?= 0

build:
	@mkdir -p dist
ifeq ($(and $(STATIC),$(filter Linux,$(shell uname))),1)
	@go build -ldflags="-linkmode external -v -extldflags '-static'" -o dist/$(BINARY_NAME) main.go
else
	@go build -o dist/$(BINARY_NAME) main.go
endif

clean:
	@rm -f dist/$(BINARY_NAME)

.PHONY: build clean
.EXPORT_ALL_VARIABLES:
