PACKAGE = sault
PACKAGEPATH = github.com/spikeekips/sault
GOPATH = $(CURDIR)/.gopath
BASE = $(GOPATH)/src/$(PACKAGEPATH)
BIN = $(GOPATH)/bin
GOLINT  = $(BIN)/golint
GO = go
ARGS = 

BUILD_COMMIT := $(shell git rev-parse HEAD 2>/dev/null)
BUILD_BRANCH := $(shell git branch | grep '^*' | sed -e 's/^* //g')
BUILD_DATE := $(shell date -u +%FT%T%z)
BUILD_REPO := $(shell git remote show origin -n | grep 'Fetch URL:' | sed -e 's/.* URL: //g')
BUILD_ENV := $(shell $(GO) env | base64)

LDFLAGS = -ldflags "-X $(PACKAGEPATH)/core.BuildVersion=${BUILD_BRANCH} -X $(PACKAGEPATH)/core.BuildCommit=${BUILD_COMMIT} -X $(PACKAGEPATH)/core.BuildDate=${BUILD_DATE} -X $(PACKAGEPATH)/core.BuildBranch=${BUILD_BRANCH} -X $(PACKAGEPATH)/core.BuildRepo=${BUILD_REPO} -X $(PACKAGEPATH)/core.BuildEnv=${BUILD_ENV}"


$(BASE):
	@mkdir -p $(dir $@)
	@rm -f $@
	@ln -sf $(CURDIR) $@
	@cd $(BASE) && $(GO) get .

$(BIN)/golint: | $(BASE)
	go get github.com/golang/lint/golint

.PHONY: clean
clean:
	@rm -f $(GOPATH)/bin/$(PACKAGE)

.PHONY: distclean
distclean:
	@rm -rf $(GOPATH)

.PHONY: clean all $(BASE)
build: | $(BASE)
	cd $(BASE) && $(GO) get && $(GO) build $(LDFLAGS) -o $(GOPATH)/bin/$(PACKAGE) main.go

.PHONY: lint
lint: $(GOLINT)
	@cd $(BASE) && $(GOLINT) ./...

.PHONY: test
test: | $(BASE)
	$(GO) get github.com/stretchr/testify/assert
	@cd $(BASE) && $(GO) test ./... $(ARGS)
