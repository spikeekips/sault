VERSION = v0.1alpha11

PACKAGE = github.com/spikeekips/sault
COMMIT_HASH = `git rev-parse HEAD 2>/dev/null`
GIT_BRANCH = `git branch | grep '^*' | sed -e 's/^* //g'`
BUILD_DATE = `date +%FT%T%z`

LDFLAGS = -ldflags "-X main.version=${VERSION} -X main.commitHash=${COMMIT_HASH} -X main.buildDate=${BUILD_DATE} -X main.gitBranch=${GIT_BRANCH}"

test:
	go test ./... -v

install: test
	go install ${LDFLAGS} .
