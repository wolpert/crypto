package com.codeheadsystems.crypto.random;

import java.security.SecureRandom;
import java.util.Random;

/**
 * BSD-Style License 2016
 */
public class KindaSecureRandomProvider extends AbstractRandomProvider {

    @Override
    public Random getFreshRandom() {
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.setSeed(secureRandom.generateSeed(16));
        return new Random(secureRandom.nextLong());
    }
}
