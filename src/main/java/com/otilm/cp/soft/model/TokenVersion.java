package com.otilm.cp.soft.model;

import java.sql.Timestamp;
import java.util.UUID;

/**
 * A token's identity, together with its version.
 *
 * @param uuid the token
 * @param name the token's name
 * @param timestamp the version of the token's row
 * @param hasCode whether a code is stored beside the keystore
 */
public record TokenVersion(UUID uuid, String name, Timestamp timestamp, boolean hasCode) {
}
