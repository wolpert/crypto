package com.codeheadsystems.crypto.manager;

import com.codeheadsystems.crypto.password.KeyParameterWrapper;

/**
 * BSD-Style License 2016
 */
public class SecondaryKey {

    private final KeyParameterWrapper keyParameterWrapper;
    private final byte[] encryptedKey;
    private final byte[] salt;

    public SecondaryKey(KeyParameterWrapper keyParameterWrapper, byte[] encryptedKey, byte[] salt) {
        this.keyParameterWrapper = keyParameterWrapper;
        this.encryptedKey = encryptedKey;
        this.salt = salt;
    }

    public KeyParameterWrapper getKeyParameterWrapper() {
        return keyParameterWrapper;
    }

    public byte[] getEncryptedKey() {
        return encryptedKey;
    }

    public byte[] getSalt() {
        return salt;
    }
}
