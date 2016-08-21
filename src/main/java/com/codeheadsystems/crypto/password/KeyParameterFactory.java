package com.codeheadsystems.crypto.password;

import com.codeheadsystems.crypto.Hasher;
import com.codeheadsystems.crypto.Utilities;
import com.codeheadsystems.crypto.random.RandomProvider;
import com.codeheadsystems.crypto.timer.TimerProvider;

import org.bouncycastle.crypto.params.KeyParameter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Timer;

import static com.codeheadsystems.crypto.Utilities.stringToBytes;
import static java.util.Objects.requireNonNull;

/**
 * BSD-Style License 2016
 */
public abstract class KeyParameterFactory {

    private static final Logger logger = LoggerFactory.getLogger(KeyParameterFactory.class);

    protected final RandomProvider randomProvider;
    protected final long expirationInMills;
    protected final Hasher hasher;
    protected final Timer timer;

    protected KeyParameterFactory(long expirationInMills, Hasher hasher, TimerProvider timerProvider) {
        this.expirationInMills = expirationInMills;
        this.hasher = requireNonNull(hasher);
        this.timer = requireNonNull(timerProvider.getTimer());
        if (!Utilities.isSecureRandomProvider()) {
            logger.error("NOT USING A SECURE RANDOM PROVIDER. USING: " + Utilities.getRandomProvider().getClass().getCanonicalName());
        }
        this.randomProvider = Utilities.getRandomProvider();
    }

    public KeyParameterWrapper generate(String password) {
        return generate(password, Utilities.randomBytes(16));
    }

    public KeyParameterWrapper generate(String password, String salt) {
        return generate(password, stringToBytes(salt));
    }

    protected ExpirationHandler generateExpirationHandler(KeyParameterWrapper keyParameterWrapper) {
        if (expirationInMills > 0) {
            return new StandardExpirationHandler(expirationInMills, timer, keyParameterWrapper);
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


    public byte[] generateRandomKey(int keysizeInBytes) {
        byte[] key = new byte[keysizeInBytes];
        randomProvider.getRandom().nextBytes(key);
        return key;
    }

    /**
     * This will return an keyParameterWrapper with no salt. No expiration monitor is set
     * for this keyParameterWrapper.
     *
     * @param keysizeInBytes
     * @return
     */
    public KeyParameter generateRandomKeyParameter(int keysizeInBytes) {
        return new KeyParameter(generateRandomKey(keysizeInBytes));
    }

    public KeyParameter generateRandom256KeyParameter() {
        return generateRandomKeyParameter(256 / 8);
    }

    public static abstract class AbstractKeyParameterFactoryBuilder<T extends KeyParameterFactory> {
        protected int iterationCount = (int) Math.pow(2, 20); // minimum is 2^14. We do 2^20 for this sensitive data
        protected long expirationInMills = 600000;
        protected TimerProvider timerProvider;

        abstract public T build();

        public AbstractKeyParameterFactoryBuilder iterationCount(int iterationCount) {
            this.iterationCount = iterationCount;
            return this;
        }

        public AbstractKeyParameterFactoryBuilder expirationInMins(int expirationInMins) {
            return expirationInMills(expirationInMins * 60000);
        }

        public AbstractKeyParameterFactoryBuilder expirationInMills(long expirationInMills) {
            this.expirationInMills = expirationInMills;
            return this;
        }

        public AbstractKeyParameterFactoryBuilder timerProvider(TimerProvider timerProvider) {
            this.timerProvider = timerProvider;
            return this;
        }
    }
}
