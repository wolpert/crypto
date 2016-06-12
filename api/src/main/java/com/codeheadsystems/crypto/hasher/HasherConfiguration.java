package com.codeheadsystems.crypto.hasher;

import java.nio.charset.Charset;

/**
 * BSD-Style License 2016
 */
public class HasherConfiguration {

    protected String digest;
    protected int saltSize;
    protected int iterations;
    protected Charset charset;
    protected int keySize;

    public HasherConfiguration(String digest, int saltSize, int iterations, Charset charset, int keySize) {
        this.digest = digest;
        this.saltSize = saltSize;
        this.iterations = iterations;
        this.charset = charset;
        this.keySize = keySize;
    }

    public String getDigest() {
        return digest;
    }

    public void setDigest(String digest) {
        this.digest = digest;
    }

    public int getSaltSize() {
        return saltSize;
    }

    public void setSaltSize(int saltSize) {
        this.saltSize = saltSize;
    }

    public int getIterations() {
        return iterations;
    }

    public void setIterations(int iterations) {
        this.iterations = iterations;
    }

    public Charset getCharset() {
        return charset;
    }

    public void setCharset(Charset charset) {
        this.charset = charset;
    }

    public int getKeySize() {
        return keySize;
    }

    public void setKeySize(int keySize) {
        this.keySize = keySize;
    }
}
