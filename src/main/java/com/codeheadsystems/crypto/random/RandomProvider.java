package com.codeheadsystems.crypto.random;

import java.util.Random;

/**
 * Created by wolpert on 7/22/16.
 */
public interface RandomProvider {

    Random getRandom();

    byte[] randomBytes(int size);
}
