package com.codeheadsystems.crypto.random;

import java.util.Random;

/**
 * Created by wolpert on 7/22/16.
 */
public class UnsecureRandomProvider extends AbstractRandomProvider {

    @Override
    public Random getFreshRandom() {
        return new Random();
    }

}
