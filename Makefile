.PHONY: check lint format-check typecheck test security build sbom verify bootstrap start docker-build
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
build:
	npm run build
sbom:
	npm run sbom
verify:
	npm run verify
bootstrap:
	npm run bootstrap
start:
	npm start
docker-build:
	docker build --pull -t syntriass-siepmu:local .
