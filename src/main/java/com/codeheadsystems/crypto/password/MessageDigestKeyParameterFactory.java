package com.codeheadsystems.crypto.password;

import com.codeheadsystems.crypto.Hasher;
import com.codeheadsystems.crypto.Utilities;
import com.codeheadsystems.crypto.hasher.HasherBuilder;
import com.codeheadsystems.crypto.hasher.MessageDigestHasherProviderImpl;

import org.bouncycastle.crypto.params.KeyParameter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Timer;

import static com.codeheadsystems.crypto.Utilities.stringToBytes;

/**
 * BSD-Style License 2016
 */
public class MessageDigestKeyParameterFactory {

    private static final Logger logger = LoggerFactory.getLogger(MessageDigestKeyParameterFactory.class);
    private final int expirationInMins;
    private final Hasher hasher;
    private final Timer timer;

    private MessageDigestKeyParameterFactory(int expirationInMins, Hasher hasher) {
        this.expirationInMins = expirationInMins;
        this.hasher = hasher;
        this.timer = new Timer(true);
    }

    public KeyParameterWrapper generate(String password) {
        return generate(password, Utilities.randomBytes(32));
    }

    public KeyParameterWrapper generate(String password, String salt) {
        return generate(password, stringToBytes(salt));
    }

    protected ExpirationHandler generateExpirationHandler(KeyParameterWrapper keyParameterWrapper) {
        if (expirationInMins > 0) {
            return new StandardExpirationHandler(expirationInMins, timer, keyParameterWrapper);
        } else {
            return new NoopExpirationHandler();
        }
    }

    /**
     * Only can be used once. The password will have to be reset
     *
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public KeyParameterWrapper generate(String password, byte[] salt) {
        logger.debug("generate()");
        byte[] hashedPassword = hasher.generateHash(password, salt).getHash();
        KeyParameter keyParameter = new KeyParameter(hashedPassword);
        KeyParameterWrapper secretKeyWrapper = new KeyParameterWrapper(keyParameter, salt);
        generateExpirationHandler(secretKeyWrapper);
        return secretKeyWrapper;
    }

    public static class Builder {
        int iterationCount = 65536;
        int expirationInMins = 10;

        public Builder iterationCount(int iterationCount) {
            this.iterationCount = iterationCount;
            return this;
        }

        public Builder expirationInMins(int expirationInMins) {
            this.expirationInMins = expirationInMins;
            return this;
        }

        public MessageDigestKeyParameterFactory build() {
            Hasher hasher = new HasherBuilder()
                    .hasherProviderClass(MessageDigestHasherProviderImpl.class)
                    .digest("SKEIN-512-256")
                    .iterations(iterationCount)
                    .build();
            return new MessageDigestKeyParameterFactory(expirationInMins, hasher);
        }
    }

}
