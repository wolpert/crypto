package com.codeheadsystems.crypto.hasher;

import com.codeheadsystems.crypto.Hasher;

/**
 * BSD-Style License 2016
 */
public class HasherBuilder {

    private int saltSize = 32;
    private int iterations = 16384;
    private int r = 8;
    private int p = 1;
    private int dkLen = 32; // bytes, not bits

    public HasherBuilder saltSize(int saltSize) {
        this.saltSize = saltSize;
        return this;
    }

    public HasherBuilder iterations(int iterations) {
        this.iterations = iterations;
        return this;
    }

    public HasherBuilder r(int r) {
        this.r = r;
        return this;
    }

    public HasherBuilder p(int p) {
        this.p = p;
        return this;
    }

    public HasherBuilder dkLen(int dkLen) {
        this.dkLen = dkLen;
        return this;
    }

    public Hasher build() {
        return new ScryptHasher(saltSize, iterations, r, p, dkLen);
    }
}
