package com.codeheadsystems.crypto.hasher;

import com.codeheadsystems.crypto.Hasher;
import com.codeheadsystems.crypto.Utilities;
import com.codeheadsystems.crypto.random.RandomProvider;

import org.bouncycastle.crypto.generators.SCrypt;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static com.codeheadsystems.crypto.Utilities.getCharset;

/**
 * Uses bouncy castle version of scrypt. Basically ignores most of the configuration
 * BSD-Style License 2016
 */
public class ScryptHasher implements Hasher {

    private static final Logger logger = LoggerFactory.getLogger(ScryptHasher.class);

    private final int saltSize; // 256 bits is good, 32 bytes
    private final int iterations; //2^14 is min
    private final int r; // 8
    private final int p; // 1
    private final int dkLen; // 32 bytes, not bits. This is for AES-256
    private final RandomProvider randomProvider;

    public ScryptHasher(int saltSize, int iterations, int r, int p, int dkLen, RandomProvider randomProvider) {
        this.saltSize = saltSize;
        this.iterations = iterations;
        this.r = r;
        this.p = p;
        this.dkLen = dkLen;
        this.randomProvider = randomProvider;
        if (iterations < 16384) {
            throw new IllegalArgumentException("Unable to have an iteration count less then 16384: found " + iterations);
        }
        logger.debug("Paranoid scrypt: n=" + iterations + " r=" + this.r + " p=" + this.p + " dkLen=" + this.dkLen);
    }

    public byte[] getSalt() {
        return randomProvider.randomBytes(saltSize);
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
        return new HashHolder(salt, internalGenerateHash(unhashedString.getBytes(getCharset()), salt));
    }

    @Override
    public HashHolder generateHash(byte[] bytes) {
        return generateHash(bytes, getSalt());
    }

    @Override
    public HashHolder generateHash(byte[] bytes, byte[] salt) {
        return new HashHolder(salt, internalGenerateHash(bytes, salt));
    }

    private byte[] internalGenerateHash(byte[] bytes, byte[] salt) {
        logger.debug("internalGenerateHash({},{})", bytes.length, salt.length);
        return SCrypt.generate(bytes, salt, iterations, r, p, dkLen);
    }

}
