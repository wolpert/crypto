package com.codeheadsystems.crypto.manager;

import com.codeheadsystems.crypto.password.KeyParameterWrapper;

/**
 * BSD-Style License 2016
 */
public class SecondaryKey {

    private KeyParameterWrapper keyParameterWrapper;
    private byte[] encryptedKey;

    public SecondaryKey(KeyParameterWrapper keyParameterWrapper, byte[] encryptedKey) {
        this.keyParameterWrapper = keyParameterWrapper;
        this.encryptedKey = encryptedKey;
    }

    public KeyParameterWrapper getKeyParameterWrapper() {
        return keyParameterWrapper;
    }

    public byte[] getEncryptedKey() {
        return encryptedKey;
    }
}
