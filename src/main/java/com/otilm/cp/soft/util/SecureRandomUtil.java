package com.otilm.cp.soft.util;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

public class SecureRandomUtil {

    private SecureRandomUtil() {
    }

    public static SecureRandom prepareSecureRandom(String algorithm, String provider) {
        try {
            return SecureRandom.getInstance(algorithm, provider);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Invalid algorithm '" + algorithm + "' for SecureRandom", e);
        } catch (NoSuchProviderException e) {
            throw new IllegalStateException("Invalid provider '" + provider + "' for SecureRandom", e);
        }
    }

}
