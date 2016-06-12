package com.codeheadsystems.crypto.hasher;

import com.codeheadsystems.crypto.Hasher;

import java.nio.charset.Charset;

import static com.codeheadsystems.crypto.Utilities.add;
import static com.codeheadsystems.crypto.Utilities.randomBytes;

/**
 * BSD-Style License 2016
 */
public abstract class AbstractSaltedHasher<T> implements Hasher {

    protected final String digest;
    protected final int saltSize;
    protected final int iterations;
    protected final Charset charset;
    protected final ThreadLocal<T> digesterThreadLocal = new ThreadLocal<>();

    public AbstractSaltedHasher(final String digest, final int saltSize, final int iterations, final Charset charset) {
        this.digest = digest;
        this.saltSize = saltSize;
        this.iterations = iterations;
        this.charset = charset;
    }

    public byte[] getSalt() {
        return randomBytes(saltSize);
    }

    public byte[] getSalt(byte[] hashedValue) {
        byte[] salt = new byte[saltSize];
        System.arraycopy(hashedValue, 0, salt, 0, saltSize);
        return salt;
    }

    protected byte[] getBytes(String hashedValue) {
        return hashedValue.getBytes(charset);
    }

    @Override
    public boolean isSame(byte[] hashedString, String unhashedString) {
        byte[] salt = getSalt(hashedString);
        byte[] newlyHashedString = generateHash(unhashedString, salt);
        return isSame(hashedString, newlyHashedString);
    }

    public boolean isSame(byte[] a1, byte[] a2) {
        if (a1 == null || a2 == null || a1.length != a2.length) {
            return false;
        }
        for (int i = 0; i < a1.length; i++) {
            if (a1[i] != a2[i]) {
                return false;
            }
        }
        return true;
    }

    @Override
    public byte[] generateHash(String unhashedString) {
        return generateHash(unhashedString, getSalt());
    }

    public byte[] generateHash(String unhashedString, byte[] salt) {
        byte[] hashingBytes = internalGenerateHash(unhashedString, salt);
        return add(salt, hashingBytes);
    }

    abstract protected byte[] internalGenerateHash(String unhashedString, byte[] salt);

}
