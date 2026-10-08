package com.otilm.cp.soft;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Holds the REST JSON of both interface generations to goldens recorded on the Spring Boot 3.5 line, so a change of
 * JSON library cannot alter what core reads or how this connector reads what core sends. Record with
 * {@code -Dwire.golden.write=true} on the 3.5 line only.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = "spring.datasource.url=jdbc:hsqldb:mem:wireGolden;sql.syntax_pgs=true")
class WireGoldenTest {

    private static final Path GOLDENS = Path.of("src/test/resources/wire");
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Pattern UUID_PATTERN = Pattern
            .compile("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");
    private static final Pattern TIMESTAMP = Pattern
            .compile("\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}(:\\d{2})?(\\.\\d+)?(Z|[+-]\\d{2}:?\\d{2})?");
    private static final Pattern EPOCH_MILLIS = Pattern.compile("\"timestamp\":\\d+");
    /** Key material and what is made with it, which a request path in a problem document only resembles. */
    private static final Pattern GENERATED_BYTES = Pattern.compile("\"(?!/v\\d/)[A-Za-z0-9+/]{40,}={0,2}\"");
    private static final Pattern CORRELATION_ID = Pattern.compile("\"correlationId\":\"[0-9a-f]{32}\"");
    private static final Pattern ASSOCIATION = Pattern.compile("\"association\":\"[A-Za-z0-9]+\"");
    /** The parser's own account of a body it could not read, which v1 quotes and each parser words differently. */
    private static final Pattern PARSER_MESSAGE = Pattern
            .compile("\"(detail|error)\":\"(?:[^\"\\\\]|\\\\.)*Source: REDACTED(?:[^\"\\\\]|\\\\.)*\"");
    /** Lists the connector builds from hash sets, so their order differs from run to run. */
    private static final Set<String> UNORDERED = Set.of("endPoints", "algorithms");
    private static final String MESSAGE = "d2lyZSBnb2xkZW4gbWVzc2FnZQ==";
    private static final String UNKNOWN_UUID = "00000000-0000-4000-8000-000000000000";
    private static final String KEY_SPEC_GROUP_UUID = "05927c10-b5ca-43cb-a69f-098885b8c307";
    private static final String KEY_ALIAS_UUID = "61a228de-c54e-461e-b0d7-ad156a547b51";
    private static final String TOKEN_CODE_UUID = "181aae19-d2a3-40ca-b5c7-570c8dfbb3cb";
    private static final String IMPORTED_KEY_REFERENCE = "3f1c6a2e-8d4b-4e7a-9c15-6b2d0e8f4a73";
    /** v3 attributes as core writes them, with the content type on the attribute and on every content item. */
    private static final String RSA_SIGNATURE = """
            {"uuid":"9180267f-c82f-4b7b-8160-d2363d813869","name":"signatureAlgorithm","contentType":"string",
             "content":[{"reference":"RSASSA-PKCS_v1.5 using SHA256","data":"SHA256withRSA","contentType":"string"}],
             "version":"v3"}""";
    private static final String ECDSA_SIGNATURE = """
            {"uuid":"9180267f-c82f-4b7b-8160-d2363d813869","name":"signatureAlgorithm","contentType":"string",
             "content":[{"reference":"ECDSA using SHA256","data":"SHA256withECDSA","contentType":"string"}],
             "version":"v3"}""";

    private final HttpClient http = HttpClient.newHttpClient();
    private final Set<String> stableUuids = new HashSet<>(Set.of(UNKNOWN_UUID, IMPORTED_KEY_REFERENCE));

    @Value("${local.server.port}")
    private int port;

    /**
     * The v1 token attributes offer a choice once any token exists, so one always does, whichever test runs first. The
     * definitions' UUIDs are constants, so they stay in the goldens; every other UUID is generated per run.
     */
    @BeforeEach
    void anchorTokenAndStableUuids() throws Exception {
        post("/v1/cryptographyProvider/tokens", """
                {"name":"wireGoldenAnchor","kind":"SOFT","attributes":%s}""".formatted(v1Token("wireGoldenAnchor")));
        stableUuids.addAll(uuidsIn(get("/v2/attributes").body()));
        stableUuids.addAll(uuidsIn(get("/v1/cryptographyProvider/SOFT/attributes").body()));
        stableUuids.addAll(uuidsIn(get("/v1/cryptographyProvider/callbacks/keyspec/RSA/attributes").body()));
    }

    @Test
    void infoAndHealth() throws Exception {
        assertGolden("v1-info", get("/v1"));
        assertGolden("v1-health", get("/v1/health"));
        assertGolden("v2-info", get("/v2/info"));
        assertGolden("v2-health", get("/v2/health"));
    }

    @Test
    void v1AttributeDefinitions() throws Exception {
        assertGolden("v1-token-attributes", get("/v1/cryptographyProvider/SOFT/attributes"));
        assertGolden("v1-token-attributes-validate",
                post("/v1/cryptographyProvider/SOFT/attributes/validate", v1Token("wireGoldenValidate")));
        assertGolden("v1-new-token-callback", get("/v1/cryptographyProvider/callbacks/token/new/attributes"));
        assertGolden("v1-rsa-key-spec-callback", get("/v1/cryptographyProvider/callbacks/keyspec/RSA/attributes"));
        assertGolden("v1-ecdsa-key-spec-callback", get("/v1/cryptographyProvider/callbacks/keyspec/ECDSA/attributes"));
    }

    @Test
    void v1TokenAndKeyLifecycle() throws Exception {
        HttpResponse<String> token = post("/v1/cryptographyProvider/tokens", """
                {"name":"wireGoldenV1","kind":"SOFT","attributes":%s}""".formatted(v1Token("wireGoldenV1")));
        assertGolden("v1-token", token);
        String tokens = "/v1/cryptographyProvider/tokens/" + JSON.readTree(token.body()).get("uuid").asText();
        assertGolden("v1-token-get", get(tokens));
        assertGolden("v1-token-status", get(tokens + "/status"));
        assertGolden("v1-token-profile-attributes", get(tokens + "/tokenProfile/attributes"));
        assertGolden("v1-activation-attributes", get(tokens + "/activate/attributes"));
        assertGolden("v1-key-pair-attributes", get(tokens + "/keys/pair/attributes"));

        HttpResponse<String> pair = post(tokens + "/keys/pair", """
                {"tokenProfileAttributes":[],"createKeyAttributes":[
                  %s,%s,
                  {"name":"data_rsaKeySize","content":[{"reference":null,"data":2048}],"version":"v2"}]}"""
                .formatted(string("data_keyAlias", "wire-v1-key"), string("data_keyAlgorithm", "RSA")));
        assertGolden("v1-key-pair", pair);
        JsonNode created = JSON.readTree(pair.body());
        String privateKey = tokens + "/keys/" + created.at("/privateKeyData/uuid").asText();
        String publicKey = tokens + "/keys/" + created.at("/publicKeyData/uuid").asText();
        assertGolden("v1-keys", get(tokens + "/keys"));
        assertGolden("v1-key-get", get(privateKey));

        String signatureAttributes = "[%s,%s]"
                .formatted(string("data_rsaSigScheme", "PKCS1-v1_5"), string("data_sigDigest", "SHA-256"));
        HttpResponse<String> signed = post(privateKey + "/sign", """
                {"signatureAttributes":%s,"data":[{"data":"%s"}]}""".formatted(signatureAttributes, MESSAGE));
        assertGolden("v1-sign", signed);
        String signature = JSON.readTree(signed.body()).at("/signatures/0/data").asText();
        assertGolden("v1-verify", post(publicKey + "/verify", """
                {"signatureAttributes":%s,"data":[{"data":"%s"}],"signatures":[{"data":"%s"}]}"""
                .formatted(signatureAttributes, MESSAGE, signature)));

        assertGolden("v1-random-attributes", get(tokens + "/keys/random/attributes"));
        assertGolden("v1-random", post(tokens + "/keys/random", """
                {"length":32,"attributes":[]}"""));
        assertGolden("v1-key-destroy", delete(privateKey));
    }

    @Test
    void v1Errors() throws Exception {
        assertGolden("v1-token-not-found", get("/v1/cryptographyProvider/tokens/" + UNKNOWN_UUID));
        assertGolden("v1-token-attributes-invalid", post("/v1/cryptographyProvider/SOFT/attributes/validate", """
                [%s]""".formatted(string("data_createTokenAction", "new"))));
        assertGolden("v1-unreadable-body", post("/v1/cryptographyProvider/tokens", "{"));
    }

    @Test
    void v2AttributeDefinitions() throws Exception {
        assertGolden("v2-definitions", get("/v2/attributes"));
        assertGolden("v2-definition", get("/v2/attributes/" + TOKEN_CODE_UUID));
        assertGolden("v2-definition-unknown", get("/v2/attributes/" + UNKNOWN_UUID));
        assertGolden("v2-callback", post("/v2/attributes/callback", callback(KEY_SPEC_GROUP_UUID, "ECDSA")));
        assertGolden("v2-callback-unsupported", post("/v2/attributes/callback", callback(KEY_ALIAS_UUID, "RSA")));
        assertGolden("v2-token-attributes", get("/v2/cryptographyProvider/tokens/attributes"));
    }

    @Test
    void v2TokenAndKeyLifecycle() throws Exception {
        String token = tokenScope("wireGoldenV2");
        assertGolden("v2-token-status", post("/v2/cryptographyProvider/tokens/status", "{" + token + "}"));
        assertGolden("v2-token-profile-attributes",
                post("/v2/cryptographyProvider/tokens/tokenProfile/attributes", "{" + token + "}"));
        assertGolden("v2-token-profile-key-usages",
                post("/v2/cryptographyProvider/tokens/tokenProfile/keyUsages", "{" + token + "}"));
        assertGolden("v2-key-request-types", post("/v2/cryptographyProvider/tokens/keyRequestTypes", """
                {%s,"tokenProfileAttributes":[]}""".formatted(token)));
        assertGolden("v2-create-key-attributes", post("/v2/cryptographyProvider/keys/create/attributes", """
                {%s,"tokenProfileAttributes":[],"keyRequestType":"keyPair"}""".formatted(token)));
        assertGolden("v2-random-attributes", post("/v2/cryptographyProvider/operations/random/attributes", """
                {%s,"tokenProfileAttributes":[]}""".formatted(token)));

        HttpResponse<String> pair = post("/v2/cryptographyProvider/keys", """
                {%s,"tokenProfileAttributes":[],"keyRequestType":"keyPair","executionMode":"synchronous",
                 "keyCreationId":"wire-v2-creation","createKeyAttributes":[
                  %s,%s,
                  {"name":"data_rsaKeySize","content":[{"reference":null,"data":2048}],"version":"v2"},
                  {"name":"keyExportable","content":[{"reference":null,"data":true}],"version":"v2"}]}"""
                .formatted(token, string("data_keyAlias", "wire-v2-key"), string("data_keyAlgorithm", "RSA")));
        assertGolden("v2-create-key", pair);
        assertGolden("v2-token-status-active", post("/v2/cryptographyProvider/tokens/status", "{" + token + "}"));
        JsonNode created = JSON.readTree(pair.body());
        String privateKey = keyScope(token, created.at("/privateKeyData/keyMeta"));
        String publicKey = keyScope(token, created.at("/publicKeyData/keyMeta"));

        assertGolden("v2-sign-attributes",
                post("/v2/cryptographyProvider/operations/sign/attributes", "{" + privateKey + "}"));
        HttpResponse<String> signed = post("/v2/cryptographyProvider/operations/sign", """
                {%s,"executionMode":"synchronous","signatureAttributes":[%s],
                 "data":[{"identifier":"one","data":"%s"}]}""".formatted(privateKey, RSA_SIGNATURE, MESSAGE));
        assertGolden("v2-sign", signed);
        String signature = JSON.readTree(signed.body()).at("/signatures/0/data").asText();
        assertGolden("v2-verify", post("/v2/cryptographyProvider/operations/verify", """
                {%s,"signatureAttributes":[%s],"data":[{"identifier":"one","data":"%s"}],
                 "signatures":[{"identifier":"one","data":"%s"}]}"""
                .formatted(publicKey, RSA_SIGNATURE, MESSAGE, signature)));
        assertGolden("v2-sign-unsupported", post("/v2/cryptographyProvider/operations/sign", """
                {%s,"executionMode":"synchronous","signatureAttributes":[%s],
                 "data":[{"identifier":"one","data":"%s"}]}""".formatted(privateKey, ECDSA_SIGNATURE, MESSAGE)));
        assertGolden("v2-export-attributes",
                post("/v2/cryptographyProvider/keys/export/attributes", "{" + privateKey + "}"));
        assertGolden("v2-key-destroy", post("/v2/cryptographyProvider/keys/destroy", """
                {%s,"executionMode":"synchronous"}""".formatted(privateKey)));
        assertGolden("v2-unreadable-body", post("/v2/cryptographyProvider/tokens/status", "{"));
    }

    @Test
    void v2KeyImport() throws Exception {
        String token = tokenScope("wireGoldenImport");
        assertGolden("v2-import-key-types", post("/v2/cryptographyProvider/keys/import/keyTypes", """
                {%s,"tokenProfileAttributes":[]}""".formatted(token)));
        assertGolden("v2-import-attributes", post("/v2/cryptographyProvider/keys/import/attributes", """
                {%s,"tokenProfileAttributes":[],"keyRequestType":"keyPair"}""".formatted(token)));
        HttpResponse<String> imported = post("/v2/cryptographyProvider/keys/import",
                Files.readString(GOLDENS.resolve("v2-import-request.json")));
        assertGolden("v2-import", imported);
        assertGolden("v2-import-result", post("/v2/cryptographyProvider/keys/import/result", """
                {%s,"keyImportId":"wire-v2-import"}""".formatted(token)));
        assertGolden("v2-export-refused",
                post("/v2/cryptographyProvider/keys/export", """
                        {%s,"keyRequestType":"keyPair","keyReference":"%s","exportKeyAttributes":[],
                         "passphrase":"wire-golden-passphrase"}"""
                        .formatted(keyScope(token, JSON.readTree(imported.body()).at("/privateKeyData/keyMeta")),
                                IMPORTED_KEY_REFERENCE)));
    }

    /** A v2 attribute as core writes it: its version, and content without a type. */
    private static String string(String name, String value) {
        return """
                {"name":"%s","content":[{"reference":"%s","data":"%s"}],"version":"v2"}"""
                .formatted(name, value, value);
    }

    /** A v1 creation answers the choice between a new and an existing token before naming the new one. */
    private static String v1Token(String name) {
        return "[" + string("data_options", "new") + "," + newToken(name).substring(1);
    }

    private static String newToken(String name) {
        return "[%s,%s,%s]".formatted(string("data_createTokenAction", "new"), string("data_newTokenName", name), """
                {"name":"data_tokenCode","content":[{"reference":"data_tokenCode",
                  "data":{"secret":"00000000","protectionLevel":null}}],"version":"v2"}""");
    }

    private static String tokenScope(String name) {
        return "\"tokenAttributes\":" + newToken(name);
    }

    private static String keyScope(String token, JsonNode keyMeta) {
        return token + ",\"tokenProfileAttributes\":[],\"keyMeta\":" + keyMeta;
    }

    private static String callback(String attributeUuid, String algorithm) {
        return """
                {"connectorInterface":"cryptography","interfaceVersion":"v2","attributeUuid":"%s",
                 "attributeName":"group_keySpecV2","contextAttributes":[],"currentAttributes":[%s]}"""
                .formatted(attributeUuid, string("data_keyAlgorithm", algorithm));
    }

    private HttpResponse<String> get(String path) throws IOException, InterruptedException {
        return send(HttpRequest.newBuilder(uri(path)).GET());
    }

    private HttpResponse<String> post(String path, String body) throws IOException, InterruptedException {
        return send(HttpRequest
                .newBuilder(uri(path))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body)));
    }

    private HttpResponse<String> delete(String path) throws IOException, InterruptedException {
        return send(HttpRequest.newBuilder(uri(path)).DELETE());
    }

    private HttpResponse<String> send(HttpRequest.Builder request) throws IOException, InterruptedException {
        return http.send(request.build(), HttpResponse.BodyHandlers.ofString());
    }

    private URI uri(String path) {
        return URI.create("http://localhost:" + port + path);
    }

    private static Set<String> uuidsIn(String text) {
        Set<String> uuids = new HashSet<>();
        Matcher matcher = UUID_PATTERN.matcher(text);
        while (matcher.find()) {
            uuids.add(matcher.group());
        }
        return uuids;
    }

    /** Masks what differs between runs: generated bytes and identifiers, and the time. */
    private String normalized(String body) {
        String masked = GENERATED_BYTES.matcher(body).replaceAll("\"<bytes>\"");
        masked = EPOCH_MILLIS.matcher(masked).replaceAll("\"timestamp\":\"<millis>\"");
        masked = CORRELATION_ID.matcher(masked).replaceAll("\"correlationId\":\"<correlation>\"");
        masked = ASSOCIATION.matcher(masked).replaceAll("\"association\":\"<association>\"");
        masked = PARSER_MESSAGE.matcher(masked).replaceAll("\"$1\":\"<parser message>\"");
        masked = TIMESTAMP
                .matcher(masked)
                .replaceAll(match -> match
                        .group()
                        .replaceAll("(Z|[+-]\\d{2}:?\\d{2})$", "<zone>")
                        .replaceAll("[0-9]", "9")
                        .replaceAll("\\.9+", ".9"));
        return UUID_PATTERN
                .matcher(masked)
                .replaceAll(match -> stableUuids.contains(match.group()) ? match.group() : "<uuid>");
    }

    /** Sorts every object's properties, since their order is not part of the contract and Jackson 3 changes it. */
    private static JsonNode canonical(JsonNode node) {
        if (node.isArray()) {
            return JSON.createArrayNode().addAll(node.valueStream().map(WireGoldenTest::canonical).toList());
        }
        if (node.isObject()) {
            ObjectNode sorted = JSON.createObjectNode();
            node
                    .properties()
                    .stream()
                    .sorted(Map.Entry.comparingByKey())
                    .forEach(field -> sorted.set(field.getKey(), canonical(field.getValue())));
            UNORDERED.stream().filter(sorted::has).forEach(name -> {
                List<JsonNode> elements = new ArrayList<>(sorted.get(name).valueStream().toList());
                elements.sort(Comparator.comparing(JsonNode::toString));
                sorted.set(name, JSON.createArrayNode().addAll(elements));
            });
            return sorted;
        }
        return node;
    }

    private void assertGolden(String name, HttpResponse<String> response) throws IOException {
        ObjectNode actual = JSON.createObjectNode();
        actual.put("status", response.statusCode());
        actual.put("contentType", response.headers().firstValue("Content-Type").map(t -> t.split(";")[0]).orElse(""));
        String body = normalized(response.body());
        actual.set("body", body.isEmpty() ? null : canonical(JSON.readTree(body)));

        Path golden = GOLDENS.resolve(name + ".json");
        if (Boolean.getBoolean("wire.golden.write")) {
            Files.writeString(golden, JSON.writerWithDefaultPrettyPrinter().writeValueAsString(actual) + "\n");
        }
        JsonNode expected = JSON.readTree(Files.readString(golden));
        assertEquals(expected, actual, "Wire output drifted from " + golden + ": " + actual);
    }
}
