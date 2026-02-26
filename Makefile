.PHONY: test-all test-go test-ts test-java test-swift test-kotlin
.PHONY: build-all build-go build-ts build-java build-swift build-kotlin
.PHONY: lint-all lint-go lint-ts lint-java lint-swift lint-kotlin
.PHONY: docs-build docs-dev clean

# Go
test-go:
	cd golang && go test -race ./...

build-go:
	cd golang && go build ./...

lint-go:
	cd golang && go vet ./...
	cd golang && staticcheck ./...

# TypeScript
test-ts:
	cd typescript && npm test

build-ts:
	cd typescript && npm run build

lint-ts:
	cd typescript && npm run lint

# Java
test-java:
	cd java && ./gradlew check

build-java:
	cd java && ./gradlew build

lint-java:
	cd java && ./gradlew check

# Swift
test-swift:
	cd swift && swift test

build-swift:
	cd swift && swift build

# Kotlin
test-kotlin:
	cd kotlin && ./gradlew check

build-kotlin:
	cd kotlin && ./gradlew build

# All
test-all: test-go test-ts test-java test-swift test-kotlin

build-all: build-go build-ts build-java build-swift build-kotlin

lint-all: lint-go lint-ts lint-java lint-swift lint-kotlin

# Docs
docs-build:
	cd docs && npm run build

docs-dev:
	cd docs && npm start

# Clean
clean:
	cd golang && go clean ./...
	rm -rf typescript/dist typescript/node_modules
	cd java && ./gradlew clean || true
	rm -rf swift/.build
	cd kotlin && ./gradlew clean || true
	rm -rf docs/build docs/.docusaurus
