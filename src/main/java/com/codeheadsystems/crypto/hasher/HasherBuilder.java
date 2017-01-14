package com.codeheadsystems.crypto.hasher;

import com.codeheadsystems.crypto.Hasher;

/**
 * BSD-Style License 2016
 */
public class HasherBuilder {

    private int saltSize = 32;
    private int iterations = 16384;

    public HasherBuilder saltSize(int saltSize) {
        this.saltSize = saltSize;
        return this;
    }

    public HasherBuilder iterations(int iterations) {
        this.iterations = iterations;
        return this;
    }

    public Hasher build() {
        return new ScryptHasher(saltSize, iterations);
    }
}
