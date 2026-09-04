package com.otilm.cp.soft.metrics;

/**
 * The events this connector counts.
 *
 * <p>
 * A caller asks for two kinds of thing: a key to come into a token or leave it, and an operation to be performed with
 * one. Both are counted, so a rising failure rate says which of them is failing.
 * </p>
 */
public enum ConnectorEvent {

    KEY_CREATED("key_created"),
    KEY_IMPORTED("key_imported"),
    KEY_EXPORTED("key_exported"),
    KEY_DESTROYED("key_destroyed"),
    DATA_SIGNED("data_signed"),
    SIGNATURE_VERIFIED("signature_verified"),
    DATA_ENCRYPTED("data_encrypted"),
    DATA_DECRYPTED("data_decrypted"),
    RANDOM_GENERATED("random_generated");

    private final String code;

    ConnectorEvent(String code) {
        this.code = code;
    }

    /**
     * @return the value the event label carries
     */
    public String getCode() {
        return code;
    }
}
