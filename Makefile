SHELL := /bin/sh

.PHONY: test script-test vet race fmt-check openldap openldap-strict openldap-full fuzz-smoke fuzz compat full

test: script-test
	go test ./... -count=1

script-test:
	./scripts/test-build-openldap-reference.sh

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

compat: fmt-check vet test openldap fuzz-smoke

full: fmt-check vet test race openldap-full fuzz
