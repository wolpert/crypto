package com.codeheadsystems.crypto.random;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Random;

/**
 * BSD-Style License 2016
 */
public abstract class AbstractRandomProvider implements RandomProvider {

    private static final Logger logger = LoggerFactory.getLogger(AbstractRandomProvider.class);

    private volatile Random random; // TODO: ThreadLocal? Note comments on Random vs ThreadLocalRandom
    private int count = 0;

    abstract protected Random getFreshRandom();

    @Override
    public synchronized Random getRandom() {
        if (count++ > 250) {
            count = 0;
            random = null;
        }
        if (random == null) {
            random = getFreshRandom();
            logger.info("New Random Generated: " + random.getClass().getCanonicalName());
        }
        return random;
    }

    @Override
    public byte[] randomBytes(int size) {
        byte[] result = new byte[size];
        getRandom().nextBytes(result);
        return result;
    }
}
