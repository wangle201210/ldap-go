SHELL := /bin/sh

.PHONY: test script-test webadmin-e2e vet staticcheck race fmt-check platform-builds openldap openldap-sdk openldap-strict openldap-full fuzz-smoke fuzz qualification-check qualification-smoke qualification-soak qualification-compare-openldap qualification-compare-openldap-100k release-check release-upgrade-gate release-build release-gate compat full

test: script-test
	go test ./... -count=1

script-test:
	./scripts/test-build-openldap-reference.sh
	./scripts/qualification/test.sh
	sh -n ./scripts/test-openldap-sdk.sh

webadmin-e2e:
	npm run test:e2e

vet:
	go vet ./...

staticcheck:
	staticcheck ./...

race:
	go test -race ./... -count=1

fmt-check:
	@files="$$(find . -type f -name '*.go' -not -path './vendor/*')"; \
	unformatted="$$(gofmt -l $$files)"; \
	if [ -n "$$unformatted" ]; then \
		printf 'gofmt is required for:\n%s\n' "$$unformatted"; \
		exit 1; \
	fi

platform-builds:
	./scripts/test-platform-builds.sh

openldap:
	./scripts/test-openldap.sh

openldap-sdk:
	./scripts/test-openldap-sdk.sh

openldap-strict:
	LDAP_GO_OPENLDAP_STRICT=1 LDAP_GO_FAIL_ON_OPTIONAL_SKIP=1 ./scripts/test-openldap.sh

openldap-full:
	./scripts/test-openldap-full.sh

fuzz-smoke:
	LDAP_GO_FUZZ_TIME=100x ./scripts/test-fuzz.sh

fuzz:
	./scripts/test-fuzz.sh

qualification-check:
	./scripts/qualification/test.sh

qualification-smoke:
	QUALIFICATION_MODE=smoke ./scripts/qualification/run.sh

qualification-soak:
	QUALIFICATION_MODE=soak ./scripts/qualification/run.sh

qualification-compare-openldap:
	./scripts/qualification/compare-openldap.sh

qualification-compare-openldap-100k:
	QUALIFICATION_COMPARE_ENTRIES=100000 \
	QUALIFICATION_COMPARE_PAGE_SIZE=10000 \
	QUALIFICATION_COMPARE_INDEXED_SEARCHES=10000 \
	QUALIFICATION_COMPARE_UNINDEXED_SEARCHES=10 \
	QUALIFICATION_COMPARE_PAGED_TRAVERSALS=2 \
	QUALIFICATION_COMPARE_MODIFICATIONS=1000 \
	QUALIFICATION_COMPARE_CONCURRENCY=8 \
	QUALIFICATION_COMPARE_SEARCHES_PER_CONNECTION=1000 \
	QUALIFICATION_COMPARE_STARTUP_TIMEOUT_SECONDS=180 \
	./scripts/qualification/compare-openldap.sh

release-check:
	./scripts/release/test.sh

release-upgrade-gate:
	./scripts/release/upgrade-gate.sh

release-build:
	./scripts/release/build-artifacts.sh

release-gate: release-check release-upgrade-gate release-build webadmin-e2e

compat: fmt-check vet platform-builds test openldap fuzz-smoke

full: fmt-check vet platform-builds test race openldap-full fuzz webadmin-e2e
