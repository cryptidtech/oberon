.PHONY: build clean cover deflake deps fmt lint test test-clean

GO=${GOENV} go

TEST_CLAUSE= $(if ${TEST}, -run ${TEST})
COVERAGE_OUT=coverage.out
PACKAGE=./...

.PHONY: build
build:
	${GO} build ${PACKAGE}

.PHONE: clean
clean:
	${GO} clean -cache -modcache -i -r
	rm -f ${COVERAGE_OUT}

.PHONY: cover
cover:
	${GO} test -short -coverprofile=${COVERAGE_OUT} ${PACKAGE}
	${GO} tool cover -html=${COVERAGE_OUT}

.PHONY: deps
deps:
	${GO} mod tidy
	if [ -d "./bls12-381" ] ; then git submodule update bls12-381; fi

.PHONY: deflake
deflake:
	${GO} test -count=1000 -timeout 0 ${TEST_CLAUSE} ${PACKAGE}

.PHONY: fmt
fmt:
	${GO} fmt ${PACKAGE}

.PHONY: lint
	${GO} vet ${PACKAGE}

.PHONY: test
	${GO} test ${TEST_CLAUSE} ${PACKAGE}

.PHONY: test-clean
	${GO} clean -testcache && ${GO} test -count=1 ${TEST_CLAUSE} ${PACKAGE}