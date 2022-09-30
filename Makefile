PKG=github.com/cyverse/sftpgo-auth-irods
VERSION=v0.1.2
GIT_COMMIT?=$(shell git rev-parse HEAD)
BUILD_DATE?=$(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS?="-X '${PKG}/commons.releaseVersion=${VERSION}' -X '${PKG}/commons.gitCommit=${GIT_COMMIT}' -X '${PKG}/commons.buildDate=${BUILD_DATE}'"
GO111MODULE=on
GOPROXY=direct
GOPATH=$(shell go env GOPATH)

.EXPORT_ALL_VARIABLES:

.PHONY: build
build:
	mkdir -p bin
	CGO_ENABLED=0 GOOS=linux go build -ldflags=${LDFLAGS} -o bin/sftpgo-auth-irods ./cmd/

.PHONY: release
release: build
	mkdir -p release
	mkdir -p release/bin
	cp bin/sftpgo-auth-irods release/bin
	cd release && tar zcvf ../sftpgo-auth-irods.tar.gz *