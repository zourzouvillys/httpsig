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
- [ ] Java OkHttp interceptor, JDK HttpClient wrapper, Spring WebClient filter
- [ ] Swift core (SPM): SFV, components, base, algorithms (CryptoKit + Security), signer/verifier + Secure Enclave
- [ ] Swift tests passing all vectors
- [ ] Swift CI workflow

## Phase 5: Swift Integrations + Kotlin Core
- [ ] Swift URLSession integration, Alamofire adapter
- [ ] Kotlin core (Gradle multi-module, JVM): SFV, components, base, algorithms, Kotlin-idiomatic API
- [ ] Kotlin tests passing all vectors
- [ ] Kotlin CI workflow

## Phase 6: Kotlin Integrations + Docs Site
- [ ] Kotlin OkHttp interceptor, Ktor plugin
- [ ] Docusaurus site: landing page, getting started, concepts, guides
- [ ] API docs generation (godoc, typedoc, javadoc, DocC, dokka)
- [ ] Docs CI workflow, cross-language CI workflow

## Phase 7: Release Automation + Polish
- [ ] Release workflows for all 5 languages
- [ ] Maven Central setup (GPG, Sonatype credentials)
- [ ] npm publish setup
- [ ] GitHub Release templates
- [ ] README badges
- [ ] SECURITY.md vulnerability reporting process
