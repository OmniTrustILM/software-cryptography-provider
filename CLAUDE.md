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

Exercise the v2 surface by hand (needs a running connector and PostgreSQL):

```bash
open docs/postman/software-cryptography-provider.postman_collection.json
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
| `util/` | Keystore, cipher, signature, X.509, secret, attribute, imported-key and migration helpers |
| `api/v2/` | Controllers implementing the NG (v2) connector interfaces, and their problem-detail advice |
| `metrics/` | The metrics the interfaces require, and the instruments that record them |
| `logging/` | The fields a log line carries, and what is taken out of them |
| `api/CorrelationFilter` | Gives every request an identifier, for the logs and for the response |
| `src/main/java/db/migration/` | Java Flyway migrations |
| `docs/postman/` | Manual test collection for the v2 surface, with a local environment |

Java packages are `com.otilm.cp.soft.*`; the migrations stay in `db.migration`, which Flyway
resolves by name.

## The v2 interfaces run alongside v1

Both generations are served at once, over the same stored keys. The v1 controllers are untouched; the v2 ones live in
`api/v2/` with their own services (`*V2Service`), so a change to one generation cannot alter the other. Class names are
suffixed `V2` because Spring derives bean names from them and `InfoControllerImpl` already exists.

**A v2 request carries its token as attributes, and there is no operation that creates one.** `TokenContextService`
turns those attributes into the token: a context asking for a new one creates it the first time it is used and finds the
same token afterwards, while a context selecting an existing one only ever finds it. Status is the exception — it
inspects without creating, and reports a token it cannot open rather than failing.

**The code arrives with every request, and there is no activation step.** A code that opens the keystore is what makes
the token usable, so resolution stores it: the operations read the stored code, and a token addressed only through v2
would otherwise have none. This is what keeps a token usable from both generations.

**A key is addressed by the metadata the connector published for it.** Each half of a key pair gets its own handle,
carrying the alias and `meta_keyReference` — the key row's own reference. The alias alone cannot distinguish the halves.

**Creation is idempotent by `keyCreationId`.** The identifier and a fingerprint of the parts of the request that
decide equivalence are columns on the key row, so what a creation leaves behind cannot outlive the key it describes. A
repeat is answered with the key the first attempt made; the same identifier on a different request is refused as a
conflict. The fingerprint covers the resolved token rather than the context that addressed it: the context carries the
code that opens the token, and a short secret would be far easier to guess from a stored hash than from the way the
code itself is stored.

**Two requests can address the same new object at once.** Only one row can carry the token name or the creation
identifier, so the database refuses the other, and that request is told to repeat itself. Recovering inside the failed
request is not possible: the failed insert leaves the persistence context unusable, so reading the winning row would
flush that insert and fail again. Repeating reaches the row the winner wrote, which is what the caller asked for.

**A key can be imported, and an imported key is a key like any other.** The platform re-protects whatever a user
supplied and sends one protection profile, PBES2 over PBKDF2-HMAC-SHA256 with AES-256-CBC, which the contract's own
envelope type checks before the connector sees it. `ImportedKeyMaterial` opens it and reads out the algorithm and both
halves: the material carries only the private key, so the public half is worked out from it. `ImportedKeyStore` then
stores the pair the way a generated one is stored, beside a self-signed certificate, taking the sizes it records from
the parameter set the key states rather than measuring them, since an encoded lattice private key carries more than
the key itself.

**A migration that has shipped anywhere is never rewritten.** Repairing a checksum realigns the schema history; it
does not run statements added to a migration a database already applied. So a change to what an applied migration
does goes into a new version, and the one that shipped stays as it was.

**A key leaves a token only if it was allowed to when it was made.** Declaring key export obliges the connector to
publish the reserved `keyExportable` attribute on its create-key schema, so a creation carries the intent and needs no
field of its own. It is added on the v2 path only: a v1 caller neither states it nor is answered by anything that
reads it. The permission is set once and never raised, so nothing about an export request can grant it.

**That permission is this connector's own policy, not the keystore's.** The contract has the intent map to the
technology's extractability control. A PKCS#12 keystore has none: every key in it can be read out with the code that
opens it. So a key marked as staying in the token is kept there by this connector refusing to export it, which is all
a keystore in software can offer. A deployment that needs the guarantee itself wants a provider backed by hardware.

**Import states its own facts on the key.** The reference the platform holds for the key, the identifier a lost
import is repeated under, the terms it was asked on, and whether the key may leave the token are columns on the key
row. The key itself is part of those terms: the platform protects the material afresh for every submission, so the
envelope says nothing about whether two imports ask for the same thing and the key's public half decides it. That is
why the material is opened before a repeat is looked for, which also means a repeat carrying the wrong passphrase is
not answered as though it had succeeded. `/import/result` answers a caller that lost the response by that identifier. An import may ask for a key that stays exportable, since
export is offered; what it states is what the key carries afterwards.

**Asynchronous execution is deliberately not offered.** `ASYNCHRONOUS` is an enforced feature flag, so declining it
means the platform only ever sends synchronous requests. Every operation here completes inline; the status and
cancellation operations answer `OPERATION_NOT_TRACKED`, and a request for asynchronous execution is refused with
`OPERATION_NOT_SUPPORTED`. Declaring the flag would mean a job store and polling for work that finishes in
milliseconds.

**Health reports the state the application already computes.** `HealthV2ControllerImpl` answers `/v2/health` and the
two probes under it by reading the health groups of the same name, so what an operator configures a group to cover is
what the platform is told, and readiness covers the database because the keystores live there. A deployment that
publishes no such groups is answered from the application's own availability state, since the contract requires both
components however the management endpoints are exposed. Only the shape is this connector's own: the management
endpoint answers in its own media type, names the probes after internal state rather than after the contract, and
reports no components on a single probe. Only statuses are published, never an indicator's details, and anything but a
connector that can serve is answered with 503. The state is read programmatically, so nothing about how the management
endpoint itself answers had to change.

**Metrics are served at `/v1/metrics`, in whichever of two formats a collector asks for.** The path is the
contract's, which numbers this interface on its own rather than with the rest of its generation, so `/v2/info`
declares it at `v1` while its siblings are `v2`. `MetricsV2ControllerImpl`
answers in OpenMetrics or in the legacy Prometheus text format, choosing by the quality values on `Accept` and by the
version named there, since that is what names the format; it sets the content type itself so that the format written
is the format declared. A collector that asks for
something neither format satisfies, or sends a header that cannot be read, is answered in the preferred format
rather than refused: the contract says so, and a misconfigured collector reading metrics is worth more than one
being told its request was unacceptable. Nothing to expose means the exposition was abandoned part-written, which is
answered as momentarily unavailable.

**The names and the buckets are read from the interfaces, not written out again.** `MetricContract` takes them from
the specification the interfaces publish, so a metric they rename fails the connector at startup instead of leaving it
publishing something nothing scrapes. `RequiredMetrics` adds only what is missing: a Spring application already
publishes when its process started, under the very name the contract asks for. What it does add goes through the
exposition library rather than the metrics facade, because the facade rewrites a meter's name into an exposed one —
dropping an `_info` suffix, appending a unit — and these names are fixed.

**The build records which commit it was made from, because the build metric has to name it.** A build with no working
copy to read it from, which is how the image is built, says as much instead; a profile supplies that, since leaving
the value unresolved fails the build outright.

**The two metrics of outbound calls are deliberately absent.** This connector makes none, and a metric of calls that
cannot happen tells a collector nothing. Everything else the interfaces require is served.

**A request is labelled by the route it matched, never by the path it asked for.** A path carries token and key
identifiers, and a series for each would grow without limit; the same holds for the method, which HTTP lets a caller
name as freely, so anything HTTP does not define is one label. The count and the timing are recorded once a request
has been served, so they describe requests that completed; a failure that escaped the whole chain has not reached the
response, and is counted under the error the container answers it with. How many requests are in flight is measured in
an interceptor instead, since the route is only known once a handler has been chosen.

**`connector_events_total` counts the work, at the layer that performs it.** A caller on either generation is
therefore counted once, and what is counted is the work rather than the answer: a request turned away before any work
began is already reported by the count of requests, under the status it was turned away with. Work inside a
transaction is counted only once that transaction has settled, since work the database went on to refuse did not
happen, and work that answers that it could not do part of what was asked — a signing request answered with an
unsigned item — is counted as having failed whatever it returned. Every event is registered at zero when the
connector starts, so a rate over something that has not happened reads as none rather than as nothing at all.

**Spring turns metrics export off under test.** It does so through the defaults property, which the test
configuration overrides with the more specific one for Prometheus. Without it there is no registry for the endpoint
to answer from and every context fails to start.

**Every request is given an identifier, and it is sent back.** `CorrelationFilter` takes it from `correlation-id`,
then `X-Request-Id`, then the trace identifier inside a `traceparent`, and mints one when a request carries none. It
goes into the logging context under `correlation_id` and into the `correlation-id` response header. A trace context
is not sent back: it belongs to the caller's trace. Problem documents read the identifier from that one place. What a
caller states is used only when it is plain printable text of a length the platform accepts, since the value reaches
both a log line and a header.

**Every line is written as the object the platform reads.** `logback-spring.xml` puts `ConnectorLogFields` on the
root of the logger tree, so what the key technology, the persistence layer and the framework say is collected the
same way as what this connector says — and those are where material could reach a log at all. The `connector.log`
schema names every field it accepts and refuses the rest, so anything beyond them goes under `attributes`: the
logger, the thread, and the stack of a failure. A trace or span identifier is written only in the shape the schema
states, since a malformed one correlates with nothing and would make the line invalid rather than incomplete. The
schema requires every line to carry a complete trace pair or a correlation identifier — that requirement is a
conditional at the end of it, not part of its `required` list — so a correlation identifier is always written: the
request's where there is one, and this run of the process where the line was said outside a request.

**What must not be written down is taken out where the line is written.** `Redaction` covers the two fields that
carry free text, the message and the stack, which is every place a line can say something. A value runs to the end of
the field rather than to the first space, since a passphrase may contain one, and a key is found by looking for the
end of it rather than by matching across it: a line carrying opening markers and no closing one would otherwise be
searched once per marker, on the thread the request is waiting on. What it cannot do is follow a value onto the next
line. It is not an appender of
its own: rewriting a message that way means standing in for the whole logging event, and the fields are the one
place every line already passes through. This connector's own lines name objects rather than material; what redaction
is for is the message of a failure raised by something that was handed a passphrase or a key.

**The service a line came from is read from the build.** `META-INF/build-info.properties` is the same file the build
metric names, so the two cannot disagree about which build is running.

**The v2 surface answers failures as RFC 9457 problem documents.** `V2ExceptionHandlingAdvice` is scoped to
`api/v2/`, so v1 keeps its own error shape. The detail is the connector's own wording, never the exception message: a
message from the key technology can quote an alias or a passphrase, and a problem document is forwarded to the platform
and logged there. Malformed context is a bad request, an absent object is not found, and a reused operation identifier
is a conflict. The connector's own log records the kind of failure and the identifier the request is known by, not the
failure itself, since that requirement covers the log as much as the response. The exception can be written down again
once log output is redacted. The handler of last resort is what keeps that boundary closed: an unforeseen failure would otherwise
reach the connector-wide advice and answer a v2 caller in the v1 shape, which carries no `errorCode`.

**The two generations correlate batch items differently.** `OperationDataMapper` is where a v1 result becomes one the
v2 contract accepts. Every item carries the identifier the request gave it, since that is all a caller has to pair a
result with what it sent. Verification is the case that bites: v2 correlates signed data and signatures by identifier,
while the code performing it pairs them by position, so the signatures are reordered to match the data before it runs.

**A v2 result item states its own outcome, which the v1 types do not.** The v1 interfaces report a failed item in the
item itself and leave its data unset, so an item that could not be signed fails the whole request rather than being
answered without a signature, and a verification that failed is reported as invalid with this connector's own wording.

**The operation attribute schemas are published for the first time.** The provider has always read `data_rsaSigScheme`,
`data_sigDigest` and the RSA cipher attributes; only v2 has endpoints for their schema, so `OperationAttributes` mints
their definitions and `AttributeDefinitionRegistry` publishes every definition the connector uses. Those attribute
UUIDs are now a contract like any other.

## Things worth knowing

**The canonical style is enforced.** The parent binds Spotless and Checkstyle to `verify`,
so `mvn verify` fails on a formatting or lint violation. `mvn spotless:apply` fixes the
formatting; Checkstyle covers what Spotless cannot, notably wildcard imports and braces. The
parent also installs a pre-commit hook on the first build that formats staged Java files.

**An attribute a request never sent reads back as an empty content, not as nothing.** The reader the interfaces
supply answers with a freshly built content object, so the value has to be reached through it and every link on the
way can be absent. Reading a link twice — once to check it, once to return it — checks one read and returns another,
which is how a code that was never sent reached a keystore as null. `AttributeValue` reads each link once and answers
absence as nothing; what to do about it belongs to the caller, since the two generations report an unreadable request
in their own way. A method that needs the code requires it itself rather than trusting the one that called it.

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
