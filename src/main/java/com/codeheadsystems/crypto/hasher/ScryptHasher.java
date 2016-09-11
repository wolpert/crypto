package com.codeheadsystems.crypto.hasher;

import com.codeheadsystems.crypto.Hasher;
import com.codeheadsystems.crypto.Utilities;

import org.bouncycastle.crypto.generators.SCrypt;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static com.codeheadsystems.crypto.Utilities.getBytes;
import static com.codeheadsystems.crypto.Utilities.randomBytes;

/**
 * Uses bouncy castle version of scrypt. Basically ignores most of the configuration
 * BSD-Style License 2016
 */
public class ScryptHasher extends AbstractSaltedHasher implements Hasher {

    private static final Logger logger = LoggerFactory.getLogger(ScryptHasher.class);

    protected final int saltSize;
    protected final int iterations;

    protected final int r = 8;
    protected final int p = 1;
    protected final int dkLen = 32; // bytes, not bits

    public ScryptHasher(HasherConfiguration hasherConfiguration) {
        super(hasherConfiguration);
        saltSize = hasherConfiguration.getSaltSize();
        iterations = hasherConfiguration.getIterations();
        logger.debug("Paranoid scrypt: n=" + iterations + " r=" + r + " p=" + p + " dkLen=" + dkLen);
    }

    public byte[] getSalt() {
        return randomBytes(saltSize);
    }

    @Override
    public String getDigest() {
        return "scrypt";
    } // Ignore what is in the config

    @Override
    public boolean isSame(HashHolder hashedString, String unhashedString) {
        HashHolder newlyHashedString = generateHash(unhashedString, hashedString.getSalt());
        return Utilities.isSame(hashedString.getHash(), newlyHashedString.getHash());
    }

    protected byte[] internalGenerateHash(byte[] bytes, byte[] salt) {
        logger.debug("internalGenerateHash(,)");
        return SCrypt.generate(bytes, salt, iterations, r, p, dkLen);
    }

}
