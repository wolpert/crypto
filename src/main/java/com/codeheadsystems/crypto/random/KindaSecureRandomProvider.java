package com.codeheadsystems.crypto.random;

import java.security.SecureRandom;
import java.util.Random;

/**
 * BSD-Style License 2016
 */
public class KindaSecureRandomProvider implements RandomProvider {
    @Override
    public Random getRandom() {
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.setSeed(secureRandom.generateSeed(16));
        return new Random(secureRandom.nextLong());
    }
}
