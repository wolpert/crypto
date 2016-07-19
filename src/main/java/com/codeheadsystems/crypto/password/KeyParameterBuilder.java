package com.codeheadsystems.crypto.password;

import org.bouncycastle.crypto.params.KeyParameter;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

/**
 * BSD-Style License 2016
 */
public class KeyParameterBuilder {

    private int keyLength = 256;
    private int iterationCount = 65536;
    private byte[] password;
    private byte[] salt;

    public KeyParameterBuilder keyLength(int keyLength) {
        this.keyLength = keyLength;
        return this;
    }

    public KeyParameterBuilder iterationCount(int iterationCount) {
        this.iterationCount = iterationCount;
        return this;
    }

    /**
     * This needs to be set if nothing else
     *
     * @param password
     * @return
     */
    public KeyParameterBuilder passwordHolder(PasswordHolder password) {
        this.password = password.getPassword();
        this.salt = password.getSalt();
        return this;
    }

    /**
     * Only can be used once. The password will have to be reset
     *
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public KeyParameterWrapper build() {
        KeyParameter keyParameter = new KeyParameter(password);
        KeyParameterWrapper secretKeyWrapper = new KeyParameterWrapper(keyParameter, salt);
        destroy();
        return secretKeyWrapper;
    }

    /**
     * This is used to allow for garbage collection.
     */
    public void destroy() {
        password = null;
        salt = null;
    }

}
