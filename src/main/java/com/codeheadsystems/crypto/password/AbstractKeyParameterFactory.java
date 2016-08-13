package com.codeheadsystems.crypto.password;

import com.codeheadsystems.crypto.Hasher;
import com.codeheadsystems.crypto.Utilities;
import com.codeheadsystems.crypto.timer.TimerProvider;

import org.bouncycastle.crypto.params.KeyParameter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Random;
import java.util.Timer;

import static com.codeheadsystems.crypto.Utilities.stringToBytes;
import static java.util.Objects.requireNonNull;

/**
 * BSD-Style License 2016
 */
public abstract class AbstractKeyParameterFactory {

    private static final Logger logger = LoggerFactory.getLogger(AbstractKeyParameterFactory.class);

    protected final Random random;
    protected final int expirationInMins;
    protected final Hasher hasher;
    protected final Timer timer;

    protected AbstractKeyParameterFactory(int expirationInMins, Hasher hasher, TimerProvider timerProvider) {
        this.expirationInMins = expirationInMins;
        this.hasher = requireNonNull(hasher);
        this.timer = requireNonNull(timerProvider.getTimer());
        if (!Utilities.isSecureRandomProvider()) {
            logger.error("NOT USING A SECURE RANDOM PROVIDER. USING: " + Utilities.getRandomProvider().getClass().getCanonicalName());
        }
        this.random = Utilities.getRandomProvider().getRandom();
    }

    public KeyParameterWrapper generate(String password) {
        return generate(password, Utilities.randomBytes(16));
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


    public byte[] generateRandomKey(int keysizeInBytes) {
        byte[] key = new byte[keysizeInBytes];
        random.nextBytes(key);
        return key;
    }

    /**
     * This will return an keyParameterWrapper with no salt. No expiration monitor is set
     * for this keyParameterWrapper.
     *
     * @param keysizeInBytes
     * @return
     */
    public KeyParameterWrapper generateRandomKeyParameter(int keysizeInBytes) {
        return new KeyParameterWrapper(new KeyParameter(generateRandomKey(keysizeInBytes)), null);
    }
}
