# CLAUDE.md

Guidance for working in this repository.

## What this is

Software Cryptography Provider — an ILM `Connector` implementing the `Cryptography Provider`
function group for kind `SOFT`. Key material lives in PKCS12 keystores held in PostgreSQL,
so this provider is intended for development and testing rather than for protecting
production keys.

Spring Boot 3 on Java 21, built with Maven.

## Commands

Build and run the tests:

```bash
mvn -B -U verify
```

Run one test class:

```bash
mvn -B test -Dtest=KeyManagementServiceImplTest
```

Coverage report (written by `verify`):

```bash
open target/site/jacoco/index.html
```

Local SonarQube scan:

```bash
mvn -B verify org.sonarsource.scanner.maven:sonar-maven-plugin:5.7.0.6970:sonar -Dsonar.token=$SONAR_TOKEN
```

## Quality gates

- Coverage at least 80%, duplication under 3%, and no open Sonar issues.
  The floor is enforced by the JaCoCo `check-coverage` rule in `pom.xml` (80% line,
  70% branch) so `mvn verify` fails before SonarCloud ever sees a regression.
- No `TODO` or `FIXME` markers.
- Every third-party GitHub Action is pinned to a full commit SHA with a trailing version
  comment, for example
  `actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1`. Reusable workflows
  from `OmniTrustILM/.github` are referenced by `@main` on purpose: that is how org-wide
  updates propagate.

## Layout

| Path | Contents |
|---|---|
| `api/` | Controllers implementing the connector interfaces, plus the attribute callback |
| `attribute/` | Attribute definitions, one class per key algorithm plus the token instance ones |
| `collection/` | Enums backing the attribute content options (curves, key sizes, security categories) |
| `service/` | Token instance, key management, cryptographic operations and the two cache services |
| `dao/` | JPA entities, repositories and the key algorithm/format/type converters |
| `util/` | Keystore, cipher, signature, X.509, secret and migration helpers |
| `src/main/java/db/migration/` | Java Flyway migrations |

Java packages are `com.otilm.cp.soft.*`; the migrations stay in `db.migration`, which Flyway
resolves by name.

## Things worth knowing

**The canonical style is enforced.** The parent binds Spotless and Checkstyle to `verify`,
so `mvn verify` fails on a formatting or lint violation. `mvn spotless:apply` fixes the
formatting; Checkstyle covers what Spotless cannot, notably wildcard imports and braces. The
parent also installs a pre-commit hook on the first build that formats staged Java files.

**Attribute identifiers are a contract.** The UUIDs and names in `attribute/` identify
attributes in the platform database. Changing one orphans the configuration of every
existing token instance. The same holds for kind `SOFT`, the `softcp` schema, the
`softcp_schema_history` Flyway table, the JSON field names and the HTTP paths. Rebranding
work must leave all of these alone.

**Shipped migrations can be edited, but their published checksum cannot change.**
`JavaMigrationChecksums` records two numbers per migration: the value `getChecksum()`
publishes to Flyway, which every deployed database holds and which must never move, and the
checksum of the source as it stands, which `DatabaseMigrationTest` asserts. Editing a shipped
migration means recording the new source checksum and leaving the published one alone.
`sonar.issue.ignore.multicriteria` in `pom.xml` exempts shipped migrations from Java rules,
listed by name so an unreleased one is still analysed.

**The image trims the JRE with jlink.** `jdeps` derives the module list from bytecode
references, so a module reached only through `ServiceLoader` has to be named in
`ADDITIONAL_MODULES` in the `Dockerfile`. `jdk.crypto.ec` is there because JSSE needs SunEC
for the ECDHE key exchange TLS 1.3 always uses: without it a JDBC URL requiring TLS fails
with `handshake_failure` and the connector does not start. The key operations name
BouncyCastle and are unaffected. Add to that variable rather than editing the jlink
invocation, and say what needs the module.

**Java migration checksums are recorded in deployed databases.** Flyway stores the value
returned by `getChecksum()`, which comes from `DatabaseMigration.JavaMigrationChecksums`
rather than from the file. Editing a migration's source — including rewriting its `import`
lines — changes the CRC32 of the file but must not change the value published to Flyway, or
validation fails on every existing installation. `DatabaseMigrationTest` asserts the two
agree, so any deliberate divergence has to be recorded explicitly.

**Two Caffeine caches sit in front of the database.** `keystores` holds decrypted key
material per token instance (60s TTL, 500 entries); `keydata` holds key rows per key UUID
(300s TTL, 10000 entries). Both are configured in `CacheConfig` and overridable under
`provider.cache.*`. `KeyStoreCacheService.evictAfterCommit` defers eviction until the
surrounding transaction commits, so a rolled-back write cannot leave a stale entry visible.

**`token_instance.code` is the only encrypted column.** It holds the PKCS12 keystore
password, and `TokenInstance.getCode()`/`setCode()` do the crypto through
`SecretsUtilHolder`, which only the Spring-managed `SecretsUtil` publishes to, from
`@PostConstruct`. Migrations and tests build their own instances without disturbing it. A JPA `AttributeConverter` would let Spring inject properly, but a
converter runs on every hydration, so `listTokenInstances()` would derive a key per row on a
path that never reads the password. Everything except the entity takes `SecretsUtil` by
injection.

**Stored secrets say how to read themselves.** The first field names the encoding:
`v2|ciphertext|salt|iv|iterations` is AES-GCM with PBKDF2-HMAC-SHA256, and is what everything
writes. `v1|ciphertext|salt|iterations` is the earlier unauthenticated scheme, still decrypted
so values written before the upgrade keep working. Nothing writes v1. Because decryption reads
whichever encoding it finds, a database left part-converted works fine.

**Key derivation costs about 50ms.** 600000 PBKDF2 iterations is deliberate, and lands only on
a `keystores` cache miss.

**The default encryption key is a published constant.** `application.yml` falls back to a
literal value when `ENCRYPTION_KEY` is unset, and `MigrationSecrets` repeats it so migrations
read what the connector wrote. `SecretsUtil` warns at startup when that default is in use.
Any installation that never set `ENCRYPTION_KEY` is encrypting with a value that is public in
this repository. Treat that as a known weakness rather than as a working default.

**`EcdsaCurveName` constants are lower case on purpose.** `asStringAttributeContentList()`
publishes `name()` as the attribute content reference, and that reference is stored against
every ECDSA key. The naming rule is suppressed on the enum rather than the constants
renamed.

**BouncyCastle's PKCS12 ignores the per-entry password.** Key bags are decrypted when the
store is loaded, so `getKey(alias, anything)` returns the key. The store password checked by
`KeyStoreUtil.loadKeystore` is the only thing protecting the material.
`KeyStoreUtilGenerationTest` records both halves of this.
