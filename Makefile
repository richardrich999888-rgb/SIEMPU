.DEFAULT_GOAL := help
.PHONY: help setup dev check lint format-check typecheck test security e2e browser build sbom ci verify bootstrap start docker-build
help:
	@echo "SIEPMU synthetic demonstrator — Node 24.19.0"
	@echo "make setup        Install locked developer dependencies (no provisioning)"
	@echo "make bootstrap    Create fresh synthetic identities; refuses existing database"
	@echo "make dev          Start relay, authority and web; bootstrap required first"
	@echo "make build        Produce allowlisted runtime bundle and file hashes"
	@echo "make test         Run unit, integration and acceptance tests"
	@echo "make lint         Run ESLint"
	@echo "make typecheck    Run strict checkJs for the tsconfig.json scope"
	@echo "make security     Run local security rules (hosted scanners are separate)"
	@echo "make e2e          Run the three required HTTP acceptance scenarios"
	@echo "make browser      Run isolated Chromium acceptance (browser installed first)"
	@echo "make ci           Run local quality, coverage, acceptance and build gates"
	@echo "make docker-build Build the container with Docker (separate hosted gate)"
setup:
	npm run setup
dev:
	npm run dev
check:
	npm run check
lint:
	npm run lint
format-check:
	npm run format:check
typecheck:
	npm run typecheck
test:
	npm test
security:
	npm run security
e2e:
	npm run test:e2e
browser:
	npm run test:browser:isolated
build:
	npm run build
sbom:
	npm run sbom
verify:
	npm run verify
ci:
	npm run ci
bootstrap:
	npm run bootstrap
start:
	npm start
docker-build:
	docker build --pull -t syntriass-siepmu:local .
