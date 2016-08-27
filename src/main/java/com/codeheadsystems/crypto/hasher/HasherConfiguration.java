package com.codeheadsystems.crypto.hasher;

/**
 * BSD-Style License 2016
 */
public class HasherConfiguration {

    private final String digest;
    private final int saltSize;
    private final int iterations;

    public HasherConfiguration(String digest, int saltSize, int iterations) {
        this.saltSize = saltSize;
        this.iterations = iterations;
        this.digest = digest;
    }

    public int getSaltSize() {
        return saltSize;
    }

    public int getIterations() {
        return iterations;
    }

    public String getDigest() {
        return digest;
    }
}
