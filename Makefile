PKG=github.com/cyverse/sftpgo-auth-irods
VERSION=v0.1.1
GO111MODULE=on
GOPROXY=direct
GOPATH=$(shell go env GOPATH)

.EXPORT_ALL_VARIABLES:

.PHONY: build
build:
	mkdir -p bin
	CGO_ENABLED=0 go build -ldflags=${LDFLAGS} -o bin/sftpgo-auth-irods ./cmd/
