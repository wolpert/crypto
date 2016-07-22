package com.codeheadsystems.crypto.random;

import java.util.Random;

/**
 * Created by wolpert on 7/22/16.
 */
public class UnsecureRandomProvider implements RandomProvider {
    @Override
    public Random getRandom() {
        return new Random();
    }
}
