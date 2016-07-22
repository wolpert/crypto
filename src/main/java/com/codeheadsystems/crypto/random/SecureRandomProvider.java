package com.codeheadsystems.crypto.random;

import java.security.SecureRandom;
import java.util.Random;

/**
 * Created by wolpert on 7/22/16.
 */
public final class SecureRandomProvider implements RandomProvider {

    @Override
    public final Random getRandom() {
        SecureRandom random = new SecureRandom();
        random.setSeed(random.generateSeed(16));
        return random;
    }
}
