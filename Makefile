# XHOOK-CLI

BINARY = xhook-cli
VERSION=0.1.0
VET_REPORT = vet.report
TEST_REPORT = tests.xml
GOARCH = amd64
DATE=$(date "+%Y%m%d%H%M%S")
GOVERSION=$(go version | cut -d" " -f3)
# VERSION=$(git describe --tags --abbrev=8 --dirty --always --long)

# Symlink into GOPATH
GITHUB_USERNAME=cheehuan
BUILD_DIR=${GOPATH}/sites/xhook-cli
CURRENT_DIR=$(shell pwd)
# BUILD_DIR_LINK=$(shell readlink ${BUILD_DIR})
PREFIX=esdata.co/xhook-control/xhook-cli/banner

# LDFLAGS="-X '${PREFIX}.Version=${VERSION}'"
# LDFLAGS="$LDFLAGS -X '${PREFIX}.BuildTime=${DATE}'"
#LDFLAGS="$LDFLAGS -X '${PREFIX}.GoVersion=${GOVERSION}'"

# Setup the -ldflags option for go build here, interpolate the variable values
LDFLAGS = -ldflags "-X ${PREFIX}.Version=${VERSION} -X ${PREFIX}.BuildTime=${DATE} -X ${PREFIX}.GoVersion=${GOVERSION}"

# Build the project
# go build -o bin/${NAME} -ldflags="${LDFLAGS}" esdata.co/xhook-control/${NAME}
# all: clean test vet linux darwin windows
all: clean linux darwin windows

linux: 
	cd ${BUILD_DIR}; \
	GOOS=linux GOARCH=${GOARCH} go build ${LDFLAGS} -o bin/${BINARY}-linux-${GOARCH} . ; \
	cd - >/dev/null

darwin:
	cd ${BUILD_DIR}; \
	GOOS=darwin GOARCH=${GOARCH} go build ${LDFLAGS} -o bin/${BINARY}-darwin-${GOARCH} . ; \
	cd - >/dev/null

windows:
	cd ${BUILD_DIR}; \
	GOOS=windows GOARCH=${GOARCH} go build ${LDFLAGS} -o bin/${BINARY}-windows-${GOARCH}.exe . ; \
	cd - >/dev/null

test:
	if ! hash go2xunit 2>/dev/null; then go install github.com/tebeka/go2xunit; fi
	cd ${BUILD_DIR}; \
	godep go test -v ./... 2>&1 | go2xunit -output ${TEST_REPORT} ; \
	cd - >/dev/null

vet:
	-cd ${BUILD_DIR}; \
	godep go vet ./... > ${VET_REPORT} 2>&1 ; \
	cd - >/dev/null

fmt:
	cd ${BUILD_DIR}; \
	go fmt $$(go list ./... | grep -v /vendor/) ; \
	cd - >/dev/null

clean:
	-rm -f ${TEST_REPORT}
	-rm -f ${VET_REPORT}
	-rm -f bin/${BINARY}-*

update_mod:
	-go mod tidy
