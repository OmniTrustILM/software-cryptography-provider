package db.migration;

import com.czertainly.cp.soft.util.DatabaseMigration;
import com.czertainly.cp.soft.util.KeyStoreUtil;
import com.czertainly.cp.soft.util.MigrationSecrets;
import com.czertainly.cp.soft.util.SecretsUtil;
import com.czertainly.cp.soft.util.X509Util;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.flywaydb.core.api.migration.BaseJavaMigration;
import org.flywaydb.core.api.migration.Context;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.sql.Types;
import java.util.Base64;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

/**
 * Migrates ML-KEM private keys from the legacy 1.3.1 storage format to the 1.4.0 format.
 *
 * <p><b>Background.</b> In 1.3.1 ML-KEM private keys were stored in the PKCS12 keystore using the
 * raw-bytes overload of {@code KeyStore.setKeyEntry(alias, byte[], null)}.  That call places a bare
 * PKCS8 key bag in the PKCS12 file with <em>no</em> accompanying certificate bag, so
 * {@code KeyStore.getCertificate(alias)} returns {@code null} for those entries.  Starting with 1.4.0,
 * the provider generates an ephemeral EC-signed orphan X.509 certificate that embeds the ML-KEM
 * public key (see {@link X509Util#generateMLKEMOrphanX509Certificate}) and stores the key via
 * {@code KeyStore.setKeyEntry(alias, PrivateKey, password, chain)}. This is inline with all other key material
 * in the connector. PKCS12 files produced by 1.3.1 fail to load correctly under the 1.4.0 BouncyCastle version
 * because the key-bag OIDs changed between the draft and the final NIST FIPS 203 standard.
 *
 * <p><b>What this migration does.</b>
 * <ol>
 *   <li>Selects every {@code token_instance} row (active and deactivated).</li>
 *   <li>Decrypts the keystore password and loads the PKCS12 blob.</li>
 *   <li>For every alias that has no associated certificate (old format) and whose recovered key
 *       algorithm starts with {@code "ML-KEM"}, the entry is identified as needing migration.</li>
 *   <li>The corresponding ML-KEM public key is fetched from the {@code key_data} table (stored there
 *       as an SPKI-encoded value when the key pair was originally created).</li>
 *   <li>A new orphan certificate is generated, the old bare key bag is removed, and a proper
 *       {@code PrivateKeyEntry} with the certificate chain is written back.</li>
 *   <li>The updated PKCS12 blob is base64-encoded and persisted to {@code token_instance.data}.</li>
 * </ol>
 *
 * <p>Deactivated tokens (those with a {@code null} code) cannot be decrypted and are skipped.
 * A WARN is logged when such a token is found to contain ML-KEM keys, because those keys will be
 * unrecoverable if the token is reactivated after an upgrade without first re-running the migration.
 * Tokens whose keystores cannot be loaded for other reasons are also skipped with a warning.
 * Aliases whose public key cannot be reconstructed are also skipped with a warning; the corresponding private key remains
 * inaccessible until the key pair is recreated.
 */
@SuppressWarnings("java:S101") // Flyway requires this naming convention (V<version>__<description>)
public class V202604211200__MigrateMLKEMKeyStorageFormat extends BaseJavaMigration {

    private static final Logger logger = LoggerFactory.getLogger(V202604211200__MigrateMLKEMKeyStorageFormat.class);

    /** Set at the start of the migration; the per-token helpers below read it. */
    private SecretsUtil secretsUtil;

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    /**
     * The JSON field name used by every {@code KeyValue} subtype (RawKeyValue, SpkiKeyValue, …)
     * to carry the base64-encoded key material.
     */
    private static final String JSON_VALUE_FIELD = "value";

    @Override
    public Integer getChecksum() {
        return DatabaseMigration.JavaMigrationChecksums.V202604211200__MigrateMLKEMKeyStorageFormat.getChecksum();
    }

    @Override
    public void migrate(Context context) throws Exception {
        secretsUtil = MigrationSecrets.forMigration();
        Security.addProvider(new BouncyCastleProvider());

        try (Statement select = context.getConnection().createStatement()) {
            ResultSet tokens = select.executeQuery(
                    "SELECT uuid, code, data FROM token_instance");

            String updateSql = "UPDATE token_instance SET data = ? WHERE uuid = ?";
            try (PreparedStatement update = context.getConnection().prepareStatement(updateSql)) {
                boolean hasBatch = false;
                while (tokens.next()) {
                    Object tokenUuid = tokens.getObject("uuid");
                    if (migrateToken(context, tokens, tokenUuid, update)) {
                        hasBatch = true;
                    }
                }
                if (hasBatch) {
                    update.executeBatch();
                }
            }
        }
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    private boolean migrateToken(Context context,
                                 ResultSet tokens,
                                 Object tokenUuid,
                                 PreparedStatement update) {
        String code;
        try {
            code = tokens.getString("code");
        } catch (Exception e) {
            logger.warn("Cannot read code column for token {}: {}", tokenUuid, e.getMessage());
            return false;
        }
        if (code == null) {
            if (tokenHasMlkemKeys(context, tokenUuid)) {
                logger.warn("Token {} is deactivated — its keystore cannot be migrated. "
                        + "If it holds ML-KEM keys, reactivate and re-run migration before upgrading.", tokenUuid);
            }
            return false;
        }

        String password;
        try {
            password = secretsUtil.decodeAndDecryptSecretString(code);
        } catch (Exception e) {
            logger.warn("Cannot decrypt password for token {}: {}", tokenUuid, e.getMessage());
            return false;
        }

        byte[] keystoreBytes;
        try {
            keystoreBytes = Base64.getDecoder().decode(tokens.getString("data"));
        } catch (Exception e) {
            logger.warn("Cannot base64-decode keystore data for token {}: {}", tokenUuid, e.getMessage());
            return false;
        }

        KeyStore ks;
        try {
            ks = KeyStoreUtil.loadKeystore(keystoreBytes, password);
        } catch (Exception e) {
            logger.warn("Cannot load keystore for token {}: {} — skipping", tokenUuid, e.getMessage());
            return false;
        }

        Map<String, PublicKey> mlkemPublicKeys = loadMlkemPublicKeysFromDb(context, tokenUuid);

        boolean modified = false;
        try {
            Enumeration<String> aliases = ks.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                if (migrateAlias(ks, alias, password, tokenUuid, mlkemPublicKeys)) {
                    modified = true;
                }
            }
        } catch (Exception e) {
            logger.warn("Error iterating aliases for token {}: {}", tokenUuid, e.getMessage());
            return false;
        }

        if (modified) {
            try {
                byte[] updatedBytes = KeyStoreUtil.saveKeystore(ks, password);
                String updatedData = Base64.getEncoder().encodeToString(updatedBytes);
                update.setString(1, updatedData);
                update.setObject(2, tokenUuid, Types.OTHER);
                update.addBatch();
                logger.info("Queued keystore update for token {}", tokenUuid);
                return true;
            } catch (Exception e) {
                logger.warn("Cannot serialise updated keystore for token {}: {}", tokenUuid, e.getMessage());
            }
        }
        return false;
    }

    /**
     * Inspects a single keystore alias.  If it is an old-format ML-KEM entry (private key present, no certificate chain),
     * migrates it to the new format in-place.
     *
     * @return {@code true} if the entry was migrated, {@code false} if it was already up to date or could not be migrated.
     */
    private boolean migrateAlias(KeyStore ks,
                                 String alias,
                                 String password,
                                 Object tokenUuid,
                                 Map<String, PublicKey> mlkemPublicKeys) {
        try {
            // New-format entries always have a certificate — skip them.
            if (ks.getCertificate(alias) != null) {
                return false;
            }

            Key key = ks.getKey(alias, password.toCharArray());
            if (key == null || !key.getAlgorithm().startsWith("ML-KEM")) {
                // Either not an ML-KEM key or the entry is corrupt; leave it alone.
                return false;
            }

            PrivateKey privateKey = (PrivateKey) key;
            PublicKey publicKey = mlkemPublicKeys.get(alias);
            if (publicKey == null) {
                logger.warn(
                        "No ML-KEM public key found in key_data for alias '{}' in token {}. "
                                + "The private key entry will not be migrated and will remain inaccessible.",
                        alias, tokenUuid);
                return false;
            }

            KeyPair keyPair = new KeyPair(publicKey, privateKey);
            X509Certificate orphanCert = X509Util.generateMLKEMOrphanX509Certificate(keyPair);

            // Remove the bare key bag and replace it with a proper PrivateKeyEntry + cert chain.
            ks.deleteEntry(alias);
            ks.setKeyEntry(alias, privateKey, password.toCharArray(), new X509Certificate[]{orphanCert});

            logger.info("Migrated ML-KEM key '{}' in token {} to new storage format", alias, tokenUuid);
            return true;

        } catch (UnrecoverableKeyException e) {
            logger.warn("Cannot recover key for alias '{}' in token {} (possibly corrupt): {}",
                    alias, tokenUuid, e.getMessage());
        } catch (Exception e) {
            logger.warn("Unexpected error migrating alias '{}' in token {}: {}",
                    alias, tokenUuid, e.getMessage());
        }
        return false;
    }

    /**
     * Queries {@code key_data} for all ML-KEM public keys belonging to the given token instance.
     *
     * <p>The {@code value} column contains JSON with a {@code "value"} field that holds the base64-encoded
     * X.509 SubjectPublicKeyInfo (SPKI) bytes. This is the format written by {@code KeyManagementServiceImpl}
     * when the key pair was originally created.
     *
     * @return a map from alias ({@code key_data.name}) to the reconstructed {@link PublicKey}.
     */
    private Map<String, PublicKey> loadMlkemPublicKeysFromDb(Context context, Object tokenUuid) {
        Map<String, PublicKey> result = new HashMap<>();
        String sql = "SELECT name, value FROM key_data "
                + "WHERE token_instance_uuid = ? AND algorithm = 'MLKEM' AND type = 'PUBLIC_KEY'";
        try (PreparedStatement ps = context.getConnection().prepareStatement(sql)) {
            ps.setObject(1, tokenUuid, Types.OTHER);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    String alias = rs.getString("name");
                    String valueJson = rs.getString(JSON_VALUE_FIELD);
                    reconstructPublicKey(alias, valueJson, tokenUuid).ifPresent(pk -> result.put(alias, pk));
                }
            }
        } catch (Exception e) {
            logger.warn("Cannot query key_data for token {}: {}", tokenUuid, e.getMessage());
        }
        return result;
    }

    private boolean tokenHasMlkemKeys(Context context, Object tokenUuid) {
        String sql = "SELECT 1 FROM key_data WHERE token_instance_uuid = ? AND algorithm = 'MLKEM' LIMIT 1";
        try (PreparedStatement ps = context.getConnection().prepareStatement(sql)) {
            ps.setObject(1, tokenUuid, Types.OTHER);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        } catch (Exception e) {
            logger.warn("Cannot check ML-KEM keys for token {}: {}", tokenUuid, e.getMessage());
            return false;
        }
    }

    /**
     * Parses the stored JSON value and reconstructs an ML-KEM {@link PublicKey}.
     */
    private java.util.Optional<PublicKey> reconstructPublicKey(String alias, String valueJson, Object tokenUuid) {
        try {
            JsonNode node = OBJECT_MAPPER.readTree(valueJson);
            JsonNode valueNode = node.get(JSON_VALUE_FIELD);
            if (valueNode == null || valueNode.isNull()) {
                logger.warn("Missing '{}' field in key_data JSON for alias '{}', token {}", JSON_VALUE_FIELD, alias, tokenUuid);
                return java.util.Optional.empty();
            }
            byte[] spkiBytes = Base64.getDecoder().decode(valueNode.asText());
            KeyFactory kf = KeyFactory.getInstance("ML-KEM", BouncyCastleProvider.PROVIDER_NAME);
            return java.util.Optional.of(kf.generatePublic(new X509EncodedKeySpec(spkiBytes)));
        } catch (Exception e) {
            logger.warn("Cannot reconstruct ML-KEM public key for alias '{}', token {}: {}", alias, tokenUuid, e.getMessage());
            return java.util.Optional.empty();
        }
    }
}
