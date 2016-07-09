package com.codeheadsystems.crypto.password;

import com.codeheadsystems.crypto.CryptoException;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * BSD-Style License 2016
 */
public class SecretKeyBuilder {

    private String algorithm = "PBKDF2WithHmacSHA512";
    private int keyLength = 128;
    private int iterationCount = 65536;
    private char[] password;
    private byte[] salt;

    public SecretKeyBuilder algorithm(String algorithm) {
        this.algorithm = algorithm;
        return this;
    }

    public SecretKeyBuilder keyLength(int keyLength) {
        this.keyLength = keyLength;
        return this;
    }

    public SecretKeyBuilder iterationCount(int iterationCount) {
        this.iterationCount = iterationCount;
        return this;
    }

    /**
     * This needs to be set if nothing else
     *
     * @param password
     * @return
     */
    public SecretKeyBuilder passwordHolder(PasswordHolder password) {
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
    public SecretKeyWrapper build() throws CryptoException {
        try {
            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(algorithm);
            PBEKeySpec spec = new PBEKeySpec(password, salt, iterationCount, keyLength);
            SecretKeyWrapper secretKeyWrapper = new SecretKeyWrapper(secretKeyFactory.generateSecret(spec), salt);
            destroy();
            return secretKeyWrapper;
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new CryptoException("Unable to generate secret key: " + e.getLocalizedMessage(), e);
        }
    }

    /**
     * This is used to allow for garbage collection.
     */
    public void destroy() {
        password = null;
        salt = null;
    }

}
