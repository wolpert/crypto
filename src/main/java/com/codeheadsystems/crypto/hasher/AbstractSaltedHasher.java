package com.codeheadsystems.crypto.hasher;

import com.codeheadsystems.crypto.Hasher;
import com.codeheadsystems.crypto.Utilities;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static com.codeheadsystems.crypto.Utilities.getCharset;
import static com.codeheadsystems.crypto.Utilities.randomBytes;

/**
 * BSD-Style License 2016
 */
public abstract class AbstractSaltedHasher<T> implements Hasher {

    protected static Logger logger = LoggerFactory.getLogger(AbstractSaltedHasher.class);

    protected final String digest;
    protected final int saltSize;
    protected final int iterations;
    protected final ThreadLocal<T> digesterThreadLocal = new ThreadLocal<>();

    public AbstractSaltedHasher(final HasherConfiguration hasherConfiguration) {
        logger.debug("AbstractSaltedHasher()");
        this.digest = hasherConfiguration.getDigest();
        this.saltSize = hasherConfiguration.getSaltSize();
        this.iterations = hasherConfiguration.getIterations();
        logger.info("constructor({},{},{},{})", digest, saltSize, iterations, this.getClass());
    }

    @Override
    public String getDigest() {
        return digest;
    }

    public byte[] getSalt() {
        return randomBytes(saltSize);
    }

    protected byte[] getBytes(String hashedValue) {
        return hashedValue.getBytes(getCharset());
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
        logger.debug("generateHash()");
        return new HashHolder(salt, internalGenerateHash(unhashedString, salt));
    }

    abstract protected byte[] internalGenerateHash(String unhashedString, byte[] salt);

}
