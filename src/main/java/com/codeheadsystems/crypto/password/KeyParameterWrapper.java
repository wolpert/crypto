package com.codeheadsystems.crypto.password;

import org.bouncycastle.crypto.params.KeyParameter;

/**
 * Created by wolpert on 7/15/16.
 */
public class KeyParameterWrapper {
    private KeyParameter keyParameter;
    private byte[] salt;

    public KeyParameterWrapper(KeyParameter keyParameter, byte[] salt) {
        this.keyParameter = keyParameter;
        this.salt = salt;
        // TODO: Timertask and exception to remove the secret key. Don't kill the salt
    }

    public KeyParameter getKeyParameter() throws SecretKeyExpiredException {
        if (keyParameter == null) {
            throw new SecretKeyExpiredException();
        }
        return keyParameter;
    }

    public byte[] salt() {
        return salt;
    }
}
