package com.czertainly.cp.soft.dao.entity;

import com.czertainly.api.model.common.attribute.common.MetadataAttribute;
import com.czertainly.api.model.connector.cryptography.token.TokenInstanceDto;
import com.czertainly.core.util.AttributeDefinitionUtils;
import com.czertainly.cp.soft.util.SecretsUtilHolder;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import jakarta.persistence.Version;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;

import java.sql.Timestamp;
import java.util.Base64;
import java.util.List;

@Entity
@Table(name = "token_instance")
public class TokenInstance extends UniquelyIdentified {

    @Column(name = "name")
    private String name;

    /** Stored encrypted; decrypted by the accessor, not on hydration. */
    @Column(name = "code")
    private String code;

    @Column(name = "data", length = Integer.MAX_VALUE)
    private String data;

    @Column(name = "metadata", length = Integer.MAX_VALUE)
    private String metadata;

    @Column(name = "timestamp")
    @Version
    private Timestamp timestamp;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getCode() {
        // Decrypted here rather than by a converter, so loading a token for any other reason
        // does not derive a key it will never use.
        return code == null ? null : SecretsUtilHolder.decrypt(code);
    }

    public void setCode(String code) {
        this.code = code == null ? null : SecretsUtilHolder.encrypt(code);
    }

    public byte[] getData() {
        return Base64.getDecoder().decode(data);
    }

    public void setData(byte[] data) {
        this.data = Base64.getEncoder().encodeToString(data);
    }

    public List<MetadataAttribute> getMetadata() {
        return AttributeDefinitionUtils.deserialize(metadata, MetadataAttribute.class);
    }

    public void setMetadata(List<MetadataAttribute> metadata) {
        this.metadata = AttributeDefinitionUtils.serialize(metadata);
    }

    public TokenInstanceDto mapToDto() {
        TokenInstanceDto dto = new TokenInstanceDto();
        dto.setUuid(this.uuid.toString());
        dto.setName(this.name);

        if (metadata != null) {
            dto.setMetadata(getMetadata());
        }

        return dto;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        TokenInstance that = (TokenInstance) o;
        return new EqualsBuilder().append(uuid, that.uuid).isEquals();
    }

    @Override
    public int hashCode() {
        return new HashCodeBuilder(17, 37).append(uuid).toHashCode();
    }

}
