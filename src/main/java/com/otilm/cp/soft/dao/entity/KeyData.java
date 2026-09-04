package com.otilm.cp.soft.dao.entity;

import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyFormat;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.connector.cryptography.key.KeyDataResponseDto;
import com.otilm.api.model.connector.cryptography.key.value.CustomKeyValue;
import com.otilm.api.model.connector.cryptography.key.value.EprkiKeyValue;
import com.otilm.api.model.connector.cryptography.key.value.KeyValue;
import com.otilm.api.model.connector.cryptography.key.value.PrkiKeyValue;
import com.otilm.api.model.connector.cryptography.key.value.RawKeyValue;
import com.otilm.api.model.connector.cryptography.key.value.SpkiKeyValue;
import com.otilm.core.util.AttributeDefinitionUtils;
import com.otilm.cp.soft.util.KeyUtil;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.util.List;
import java.util.UUID;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.hibernate.annotations.ColumnDefault;

@Entity
@Table(name = "key_data", uniqueConstraints = {
        @UniqueConstraint(name = "key_data_key_creation_id_key", columnNames = {"key_creation_id", "type"}),
        @UniqueConstraint(name = "key_data_key_import_id_key", columnNames = {"key_import_id", "type"}),
        @UniqueConstraint(name = "key_data_platform_reference_key", columnNames = {"platform_reference", "type"})})
public class KeyData extends UniquelyIdentified {

    @Column(name = "name")
    private String name;

    @Column(name = "association")
    private String association;

    @Column(name = "type")
    private KeyType type;

    @Column(name = "algorithm")
    private KeyAlgorithm algorithm;

    @Column(name = "format")
    private KeyFormat format;

    @Column(name = "value", length = Integer.MAX_VALUE)
    private String value;

    @Column(name = "length")
    private int length;

    @Column(name = "metadata", length = Integer.MAX_VALUE)
    private String metadata;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "token_instance_uuid", insertable = false, updatable = false)
    private TokenInstance tokenInstance;

    @Column(name = "token_instance_uuid")
    private UUID tokenInstanceUuid;

    /**
     * The identifier of the creation that produced the key, under which a caller repeats a creation whose answer it
     * lost. A key created through the v1 interfaces has none.
     */
    @Column(name = "key_creation_id", length = 256)
    private String keyCreationId;

    /**
     * A fingerprint of the terms the creation was asked on, which tells a repeat from a different request wearing the
     * same identifier.
     */
    @Column(name = "creation_fingerprint", length = 64)
    private String creationFingerprint;

    /**
     * The identity the platform gave an imported key, which it never reads back from a response and addresses the key
     * by afterwards. A key this provider generated has none.
     */
    @Column(name = "platform_reference")
    private UUID platformReference;

    /**
     * The identifier of the import that produced the key, under which a caller repeats an import whose answer it lost
     * and asks what became of one. A key this provider generated has none.
     */
    @Column(name = "key_import_id", length = 256)
    private String keyImportId;

    /**
     * A fingerprint of the terms the import was asked on, which tells a repeat from a different request wearing the
     * same identifier. The platform protects the material afresh every time, so the envelope cannot decide it.
     */
    @Column(name = "import_fingerprint", length = 64)
    private String importFingerprint;

    /**
     * Whether the key may ever leave the token. Only an import states it, so a generated key never may, and a row
     * written without stating it is such a key. The default is declared here as well as in the migration: a schema
     * built from these mappings has to accept the same statements the migrated one does.
     */
    @Column(name = "exportable", nullable = false)
    @ColumnDefault("false")
    private boolean exportable;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getAssociation() {
        return association;
    }

    public void setAssociation(String association) {
        this.association = association;
    }

    public KeyType getType() {
        return type;
    }

    public void setType(KeyType type) {
        this.type = type;
    }

    public KeyAlgorithm getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(KeyAlgorithm algorithm) {
        this.algorithm = algorithm;
    }

    public KeyFormat getFormat() {
        return format;
    }

    public void setFormat(KeyFormat format) {
        this.format = format;
    }

    public KeyValue getValue() {
        switch (format) {
            case RAW:
                return KeyUtil.deserializeKeyValue(value, RawKeyValue.class);
            case SPKI:
                return KeyUtil.deserializeKeyValue(value, SpkiKeyValue.class);
            case PRKI:
                return KeyUtil.deserializeKeyValue(value, PrkiKeyValue.class);
            case EPRKI:
                return KeyUtil.deserializeKeyValue(value, EprkiKeyValue.class);
            case CUSTOM:
                return KeyUtil.deserializeKeyValue(value, CustomKeyValue.class);
            default:
                throw new IllegalArgumentException("Unsupported key format: " + format);
        }
    }

    public void setValue(KeyValue value) {
        this.value = KeyUtil.serializeKeyValue(value);
    }

    public int getLength() {
        return length;
    }

    public void setLength(int length) {
        this.length = length;
    }

    public List<MetadataAttribute> getMetadata() {
        return AttributeDefinitionUtils.deserialize(metadata, MetadataAttribute.class);
    }

    public void setMetadata(List<MetadataAttribute> metadata) {
        this.metadata = AttributeDefinitionUtils.serialize(metadata);
    }

    public TokenInstance getTokenInstance() {
        return tokenInstance;
    }

    public void setTokenInstance(TokenInstance tokenInstance) {
        this.tokenInstance = tokenInstance;
        if (tokenInstance != null) {
            this.tokenInstanceUuid = tokenInstance.getUuid();
        } else {
            this.tokenInstanceUuid = null;
        }
    }

    public UUID getTokenInstanceUuid() {
        return tokenInstanceUuid;
    }

    public void setTokenInstanceUuid(UUID tokenInstanceUuid) {
        this.tokenInstanceUuid = tokenInstanceUuid;
    }

    public String getKeyCreationId() {
        return keyCreationId;
    }

    public void setKeyCreationId(String keyCreationId) {
        this.keyCreationId = keyCreationId;
    }

    public String getCreationFingerprint() {
        return creationFingerprint;
    }

    public void setCreationFingerprint(String creationFingerprint) {
        this.creationFingerprint = creationFingerprint;
    }

    public UUID getPlatformReference() {
        return platformReference;
    }

    public void setPlatformReference(UUID platformReference) {
        this.platformReference = platformReference;
    }

    public String getKeyImportId() {
        return keyImportId;
    }

    public void setKeyImportId(String keyImportId) {
        this.keyImportId = keyImportId;
    }

    public String getImportFingerprint() {
        return importFingerprint;
    }

    public void setImportFingerprint(String importFingerprint) {
        this.importFingerprint = importFingerprint;
    }

    public boolean isExportable() {
        return exportable;
    }

    public void setExportable(boolean exportable) {
        this.exportable = exportable;
    }

    public com.otilm.api.model.connector.cryptography.key.KeyData toKeyData() {
        com.otilm.api.model.connector.cryptography.key.KeyData keyData = new com.otilm.api.model.connector.cryptography.key.KeyData();
        keyData.setType(getType());
        keyData.setAlgorithm(getAlgorithm());
        keyData.setFormat(getFormat());
        keyData.setValue(getValue());
        keyData.setLength(getLength());
        keyData.setMetadata(getMetadata());

        return keyData;
    }

    public KeyDataResponseDto toKeyDataResponseDto() {
        com.otilm.api.model.connector.cryptography.key.KeyData keyData = toKeyData();

        KeyDataResponseDto keyDataResponseDto = new KeyDataResponseDto();
        keyDataResponseDto.setUuid(getUuid().toString());
        keyDataResponseDto.setName(getName());
        keyDataResponseDto.setAssociation(getAssociation());
        keyDataResponseDto.setKeyData(keyData);

        return keyDataResponseDto;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        KeyData that = (KeyData) o;
        return new EqualsBuilder().append(uuid, that.uuid).isEquals();
    }

    @Override
    public int hashCode() {
        return new HashCodeBuilder(17, 37).append(uuid).toHashCode();
    }
}
