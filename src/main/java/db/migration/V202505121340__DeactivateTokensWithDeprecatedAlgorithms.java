package db.migration;

import com.czertainly.cp.soft.util.DatabaseMigration;
import com.czertainly.cp.soft.util.KeyStoreUtil;
import com.czertainly.cp.soft.util.MigrationSecrets;
import com.czertainly.cp.soft.util.SecretsUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.flywaydb.core.api.migration.BaseJavaMigration;
import org.flywaydb.core.api.migration.Context;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.Security;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.sql.Types;
import java.util.Base64;

@SuppressWarnings("java:S101")
public class V202505121340__DeactivateTokensWithDeprecatedAlgorithms extends BaseJavaMigration {
    private static final Logger logger = LoggerFactory.getLogger(V202505121340__DeactivateTokensWithDeprecatedAlgorithms.class);

    @Override
    public Integer getChecksum() {
        return DatabaseMigration.JavaMigrationChecksums.V202505121340__DeactivateTokensWithDeprecatedAlgorithms.getChecksum();
    }

    @Override
    public void migrate(Context context) throws Exception {
        SecretsUtil secretsUtil = MigrationSecrets.forMigration();
        Security.addProvider(new BouncyCastleProvider());

        try (final Statement select = context.getConnection().createStatement()) {
            ResultSet tokens = select.executeQuery("SELECT uuid, code, data FROM token_instance WHERE code IS NOT NULL;");
            String updateTokenData = "UPDATE token_instance SET code = null WHERE uuid = ?;";
            try (PreparedStatement preparedStatement = context.getConnection().prepareStatement(updateTokenData)) {
                while (tokens.next()) {
                    String password;
                    try {
                        password = secretsUtil.decodeAndDecryptSecretString(tokens.getString("code"));
                    } catch (Exception e) {
                        logger.info("Cannot decrypt password of token instance with UUID {}: {}", tokens.getObject("uuid"), e.getMessage());
                        continue;
                    }
                    try {
                        KeyStoreUtil.loadKeystore(Base64.getDecoder().decode(tokens.getString("data")), password);
                    } catch (Exception e) {
                        preparedStatement.setObject(1, tokens.getObject("uuid"), Types.OTHER);
                        preparedStatement.addBatch();
                    }
                }
                preparedStatement.executeBatch();
            }
        }
    }

}
