package com.codeheadsystems.crypto.password;

import javax.crypto.SecretKey;

/**
 * Secret key wrapper that will auto-destroy after a time limit
 * <p/>
 * BSD-Style License 2016
 */
public class SecretKeyWrapper {

    private SecretKey secretKey;
    private byte[] salt;

    public SecretKeyWrapper(SecretKey secretKey, byte[] salt) {
        this.secretKey = secretKey;
        this.salt = salt;
        // TODO: Timertask and exception to remove the secret key. Don't kill the salt
    }

    public SecretKey getSecretKey() throws SecretKeyExpiredException {
        if (secretKey == null) {
            throw new SecretKeyExpiredException();
        }
        return secretKey;
    }

    public byte[] salt() {
        return salt;
    }
}
