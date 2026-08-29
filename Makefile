SHELL := /bin/sh

.PHONY: test script-test vet race fmt-check platform-builds openldap openldap-strict openldap-full fuzz-smoke fuzz qualification-check qualification-smoke qualification-soak release-check release-upgrade-gate release-build release-gate compat full

test: script-test
	go test ./... -count=1

script-test:
	./scripts/test-build-openldap-reference.sh
	./scripts/qualification/test.sh

vet:
	go vet ./...

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

openldap-strict:
	LDAP_GO_FAIL_ON_OPTIONAL_SKIP=1 ./scripts/test-openldap.sh

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

release-check:
	./scripts/release/test.sh

release-upgrade-gate:
	./scripts/release/upgrade-gate.sh

release-build:
	./scripts/release/build-artifacts.sh

release-gate: release-check release-upgrade-gate release-build

compat: fmt-check vet platform-builds test openldap fuzz-smoke

full: fmt-check vet platform-builds test race openldap-full fuzz
