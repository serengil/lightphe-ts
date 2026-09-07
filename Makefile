NPM ?= npm
NPX ?= npx

.DEFAULT_GOAL := help
.PHONY: help install format format-check lint lint-fix typecheck test test-watch \
        coverage build clean check version-patch version-minor version-major \
        publish publish-dry release

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

install: ## Install dependencies from the lockfile
	$(NPM) ci

format: ## Format the source with Prettier
	$(NPX) prettier --write "**/*.{ts,js,mjs,json,md,yml}"

format-check: ## Fail if anything is not formatted
	$(NPX) prettier --check "**/*.{ts,js,mjs,json,md,yml}"

lint: ## Lint with ESLint
	$(NPX) eslint .

lint-fix: ## Lint and apply the fixes ESLint can make
	$(NPX) eslint . --fix

typecheck: ## Type-check without emitting anything
	$(NPX) tsc -p tsconfig.json --noEmit

test: ## Run the unit tests
	$(NPX) jest

test-watch: ## Re-run the unit tests on change
	$(NPX) jest --watch

coverage: ## Run the unit tests and report coverage
	$(NPX) jest --coverage

build: ## Build the CommonJS, ESM and type-declaration outputs into dist/
	$(NPM) run build

clean: ## Remove build and coverage artifacts
	$(NPX) rimraf dist coverage

check: format-check lint typecheck test ## Everything CI runs, in one target

# --- release ----------------------------------------------------------------
# Bump, then `make publish`. Publishing runs the build through prepublishOnly,
# so dist/ is always rebuilt from the current sources.

version-patch: ## Bump the patch version and tag it
	$(NPM) version patch

version-minor: ## Bump the minor version and tag it
	$(NPM) version minor

version-major: ## Bump the major version and tag it
	$(NPM) version major

# npm accounts with two-factor auth on need a one-time password to publish.
# Pass it through as `make publish OTP=123456`; without it npm prompts, or
# fails outright when stdin is not a terminal.
OTP ?=
OTP_FLAG = $(if $(OTP),--otp=$(OTP),)

publish-dry: build ## Show exactly what would be published, without publishing
	$(NPM) publish --dry-run --access public

publish: ## Publish to npm. With 2FA on: make publish OTP=123456
	$(NPM) publish --access public $(OTP_FLAG)

release: check publish ## Verify everything, then publish (accepts OTP=... too)
	@echo "released $$($(NPM) pkg get version | tr -d '\"')"
	@echo "remember to push the tag: git push --follow-tags"
