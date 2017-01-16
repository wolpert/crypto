package com.codeheadsystems.crypto.password;

import com.codeheadsystems.crypto.Hasher;
import com.codeheadsystems.crypto.Utilities;
import com.codeheadsystems.crypto.hasher.HasherBuilder;
import com.codeheadsystems.crypto.random.RandomProvider;

import org.bouncycastle.crypto.params.KeyParameter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static com.codeheadsystems.crypto.Utilities.stringToBytes;
import static com.codeheadsystems.crypto.cipher.CipherProvider.KEY_BYTE_SIZE;
import static java.util.Objects.requireNonNull;

/**
 * BSD-Style License 2016
 */
public class KeyParameterFactory {

    private static final Logger logger = LoggerFactory.getLogger(KeyParameterFactory.class);

    private final RandomProvider randomProvider;
    private final long expirationInMills;
    private final Hasher hasher;

    protected KeyParameterFactory(long expirationInMills, Hasher hasher) {
        this.expirationInMills = expirationInMills;
        this.hasher = requireNonNull(hasher);
        if (!Utilities.isSecureRandomProvider()) {
            logger.error("NOT USING A SECURE RANDOM PROVIDER. USING: " + Utilities.getRandomProvider().getClass().getCanonicalName());
        }
        this.randomProvider = Utilities.getRandomProvider();
    }

    public KeyParameterWrapper generate(String password, String salt) {
        return generate(password, stringToBytes(salt));
    }

    /**
     * Hashes the password and salt together to create a secure key that can be
     * used for AES encryption. The salt can be generated from this class, but you
     * need to store the salt and re-use it when using this password to decrypt the content.
     *
     * @param password The super-secret password from the end user
     * @param salt     The one-time use salt that should be stored with the content being encrypted.
     * @return an AES key wrapped with an expiration wrapper, if the key factory was configured to create expiring keys
     */
    public KeyParameterWrapper generate(String password, byte[] salt) {
        logger.debug("generate()");
        byte[] hashedPassword = hasher.generateHash(password, salt).getHash();
        KeyParameter keyParameter = new KeyParameter(hashedPassword);
        return getExpirableKeyParameterWrapper(keyParameter);
    }

    public KeyParameterWrapper getExpirableKeyParameterWrapper(KeyParameter keyParameter) {
        return new KeyParameterWrapper(keyParameter, expirationInMills);
    }


    public byte[] generateRandomKey(int keysizeInBytes) {
        byte[] key = new byte[keysizeInBytes];
        randomProvider.getRandom().nextBytes(key);
        return key;
    }

    /**
     * This will return an keyParameterWrapper with no salt. No expiration monitor is set
     * for this keyParameterWrapper.
     *
     * @param keysizeInBytes how many bytes to use. Must be value for AES keys
     * @return a random keyParameter
     */
    public KeyParameter generateRandomKeyParameter(int keysizeInBytes) {
        return new KeyParameter(generateRandomKey(keysizeInBytes));
    }

    public KeyParameter generateRandom256KeyParameter() {
        return generateRandomKeyParameter(256 / 8);
    }

    public KeyParameterWrapper generateRandom256KeyParameterWrapper() {
        KeyParameter keyParameter = generateRandom256KeyParameter();
        return getExpirableKeyParameterWrapper(keyParameter);
    }

    public static class Builder {
        private int iterationCount = (int) Math.pow(2, 20); // minimum is 2^14. We do 2^20 for this sensitive data
        private long expirationInMills = 600000;

        public KeyParameterFactory build() {
            Hasher hasher = new HasherBuilder()
                    .iterations(iterationCount)
                    .saltSize(KEY_BYTE_SIZE) // 256 bit
                    .build();
            return new KeyParameterFactory(expirationInMills, hasher);
        }

        public Builder iterationCount(int iterationCount) {
            if (iterationCount < 16384) {
                throw new IllegalArgumentException("Unable to have an iteration count less then 16384: found " + iterationCount);
            }
            this.iterationCount = iterationCount;
            return this;
        }

        public Builder expirationInMins(int expirationInMins) {
            return expirationInMills(expirationInMins * 60000);
        }

        public Builder expirationInMills(long expirationInMills) {
            this.expirationInMills = expirationInMills;
            return this;
        }
    }
}
