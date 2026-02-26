# httpsig TODO

## Phase 1: Scaffolding + Go Core
- [x] Repo scaffolding (.gitignore, .editorconfig, LICENSE, README, CLAUDE.md, CONTRIBUTING, SECURITY, Makefile)
- [x] Shared test vectors (testdata/keys, testdata/vectors, schema)
- [x] Go core: SFV subset, components, signature base, algorithms, keys, signer, verifier, digest, errors
- [x] Go tests passing all RFC 9421 Appendix B vectors
- [x] Go CI workflow (.github/workflows/go.yml)

## Phase 2: Go Integrations + TypeScript Core
- [x] Go net/http middleware (signing RoundTripper, verifying Handler)
- [x] TypeScript core: SFV, components, base, algorithms (node:crypto + Web Crypto), async signer/verifier
- [x] TypeScript tests passing all vectors
- [x] TypeScript CI workflow

## Phase 3: TypeScript Integrations + Java Core
- [x] TypeScript fetch wrapper, axios interceptor, undici interceptor
- [x] Java core (Gradle multi-module): SFV, components, base, algorithms, signer/verifier
- [x] Java tests passing all vectors
- [x] Java CI workflow

## Phase 4: Java Integrations + Swift Core
- [x] Java OkHttp interceptor, JDK HttpClient wrapper, Spring WebClient filter
- [x] Swift core (SPM): SFV, components, base, algorithms (CryptoKit + Security), signer/verifier + Secure Enclave
- [x] Swift tests passing all vectors
- [x] Swift CI workflow

## Phase 5: Swift Integrations + Kotlin Core
- [x] Swift URLSession integration, Alamofire adapter
- [x] Kotlin core (Gradle multi-module, JVM): SFV, components, base, algorithms, Kotlin-idiomatic API
- [x] Kotlin tests passing all vectors
- [x] Kotlin CI workflow

## Phase 6: Kotlin Integrations + Docs Site
- [x] Kotlin OkHttp interceptor, Ktor plugin
- [x] Docusaurus site: landing page, getting started, concepts, guides
- [ ] API docs generation (godoc, typedoc, javadoc, DocC, dokka)
- [x] Docs CI workflow, cross-language CI workflow

## Phase 7: Release Automation + Polish
- [ ] Release workflows for all 5 languages
- [ ] Maven Central setup (GPG, Sonatype credentials)
- [ ] npm publish setup
- [ ] GitHub Release templates
- [ ] README badges
- [ ] SECURITY.md vulnerability reporting process
