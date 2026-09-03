package com.otilm.cp.soft.dao.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.time.OffsetDateTime;
import java.util.UUID;

/**
 * What one key creation produced, kept so that repeating the request answers with the same key.
 *
 * <p>
 * A caller that loses the response repeats it with the same creation identifier, and must be given the key the first
 * attempt made rather than a second key. The fingerprint is what tells a repeat from a different request wearing the
 * same identifier, which the contract answers as a conflict.
 * </p>
 */
@Entity
@Table(name = "key_creation_record", uniqueConstraints = @UniqueConstraint(name = "key_creation_record_creation_id_key",
        columnNames = "creation_id"))
public class KeyCreationRecord extends UniquelyIdentified {

    @Column(name = "creation_id", nullable = false, length = 256)
    private String creationId;

    @Column(name = "token_instance_uuid", nullable = false)
    private UUID tokenInstanceUuid;

    @Column(name = "request_fingerprint", nullable = false, length = 64)
    private String requestFingerprint;

    @Column(name = "public_key_uuid", nullable = false)
    private UUID publicKeyUuid;

    @Column(name = "private_key_uuid", nullable = false)
    private UUID privateKeyUuid;

    @Column(name = "created_at", nullable = false)
    private OffsetDateTime createdAt;

    public String getCreationId() {
        return creationId;
    }

    public void setCreationId(String creationId) {
        this.creationId = creationId;
    }

    public UUID getTokenInstanceUuid() {
        return tokenInstanceUuid;
    }

    public void setTokenInstanceUuid(UUID tokenInstanceUuid) {
        this.tokenInstanceUuid = tokenInstanceUuid;
    }

    public String getRequestFingerprint() {
        return requestFingerprint;
    }

    public void setRequestFingerprint(String requestFingerprint) {
        this.requestFingerprint = requestFingerprint;
    }

    public UUID getPublicKeyUuid() {
        return publicKeyUuid;
    }

    public void setPublicKeyUuid(UUID publicKeyUuid) {
        this.publicKeyUuid = publicKeyUuid;
    }

    public UUID getPrivateKeyUuid() {
        return privateKeyUuid;
    }

    public void setPrivateKeyUuid(UUID privateKeyUuid) {
        this.privateKeyUuid = privateKeyUuid;
    }

    public OffsetDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(OffsetDateTime createdAt) {
        this.createdAt = createdAt;
    }
}
