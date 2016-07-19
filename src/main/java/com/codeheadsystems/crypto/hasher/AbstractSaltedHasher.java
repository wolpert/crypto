package com.codeheadsystems.crypto.hasher;

import com.codeheadsystems.crypto.Hasher;
import com.codeheadsystems.crypto.Utilities;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.Charset;

import static com.codeheadsystems.crypto.Utilities.randomBytes;

/**
 * BSD-Style License 2016
 */
public abstract class AbstractSaltedHasher<T> implements Hasher {

    protected static Logger logger = LoggerFactory.getLogger(AbstractSaltedHasher.class);

    protected final String digest;
    protected final int saltSize;
    protected final int iterations;
    protected final Charset charset;
    protected final ThreadLocal<T> digesterThreadLocal = new ThreadLocal<>();

    public AbstractSaltedHasher(final HasherConfiguration hasherConfiguration) {
        this.digest = hasherConfiguration.digest;
        this.saltSize = hasherConfiguration.saltSize;
        this.iterations = hasherConfiguration.iterations;
        this.charset = hasherConfiguration.charset;
        logger.info("constructor({},{},{},{},{})", digest, saltSize, iterations, charset, this.getClass());
    }

    @Override
    public String getDigest() {
        return digest;
    }

    public byte[] getSalt() {
        return randomBytes(saltSize);
    }

    protected byte[] getBytes(String hashedValue) {
        return hashedValue.getBytes(charset);
    }

    @Override
    public boolean isSame(HashHolder hashedString, String unhashedString) {
        HashHolder newlyHashedString = generateHash(unhashedString, hashedString.getSalt());
        return Utilities.isSame(hashedString.getHash(), newlyHashedString.getHash());
    }


    @Override
    public HashHolder generateHash(String unhashedString) {
        return generateHash(unhashedString, getSalt());
    }

    @Override
    public HashHolder generateHash(String unhashedString, byte[] salt) {
        return new HashHolder(salt, internalGenerateHash(unhashedString, salt));
    }

    abstract protected byte[] internalGenerateHash(String unhashedString, byte[] salt);

}
